import base64
import os
import sys

from barbican.common import utils
from cffi import FFI
from OpenSSL.crypto import load_publickey, load_certificate, X509, dump_publickey
from OpenSSL.crypto import X509Store, verify, X509StoreContext, FILETYPE_PEM
from ecdsa import SigningKey, NIST256p, VerifyingKey
import unicodedata

LOG = utils.getLogger(__name__)

class Secret:

    def __init__(self, value=None, length=None):
        self.value=value
        self.length=length

class SGXInterface:

    def __init__(self):
        LOG.info("SGX Interface initialized")

        self.ffi = FFI()
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(os.path.join(dir_path,"sgx.h")) as stream:
            self.ffi.cdef(stream.read())

        self.ffi.set_source("_sgx_interface",
            """
            #include "sgx_eid.h"
            #include "sgx_key_exchange.h"
            #include "common.h"
            #include "network_ra.h"
            #include "barbie_server.h"
            #include "barbie_client.h"
            #include "ra_client.h"
            #include "ra_server.h"
            #include <stdbool.h>
            #include "service_provider.h"
            """,
            include_dirs=['/usr/include', '/opt/intel/sgxsdk/include'],
            library_dirs=['/usr/local/lib', '/opt/intel/sgxsdk/lib64/'],
            libraries=["sample_libcrypto", "BarbiE_Client", "BarbiE_Server"])

        self.ffi.compile(tmpdir=dir_path)

        libuae = self.ffi.dlopen("sgx_uae_service", self.ffi.RTLD_GLOBAL)
        liburts = self.ffi.dlopen("sgx_urts", self.ffi.RTLD_GLOBAL)
        libcrypto = self.ffi.dlopen("sample_libcrypto", self.ffi.RTLD_GLOBAL)

        self.barbie_s = self.ffi.dlopen("BarbiE_Server", self.ffi.RTLD_LAZY)
        self.barbie_c = self.ffi.dlopen("BarbiE_Client", self.ffi.RTLD_LAZY)
        self.iv = 12
        self.mac = 16
        self.error_dict = {'0':'SP_OK', '1':'SP_UNSUPPORTED_EXTENDED_EPID_GROUP', '2':'SP_INTEGRITY_FAILED', '3':'SP_QUOTE_VERIFICATION_FAILED', '4':'SP_IAS_FAILED', '5':'SP_INTERNAL_ERROR', '6':'SP_PROTOCOL_ERROR', '7':'SP_QUOTE_VERSION_ERROR', '8':'SP_SPID_SET_ERROR'}

    def init_env_variables(self):
        separator = "="
        with open("/opt/BarbiE/env.properties") as f:
            for line in f:
                if separator in line:
                    name, value = line.split(separator)
                    os.environ[name.strip()] = value.strip()

    def get_spid(self):
        separator = "="
        spid = None
        with open("/opt/BarbiE/env.properties") as f:
            for line in f:
                if separator in line:
                    name, value = line.split(separator)
                    if name.strip() == "IAS_SPID":
                        spid =  value.strip()
                        return spid

    def get_ias_crt(self):
        separator = "="
        ias_crt = None
        with open("/opt/BarbiE/env.properties") as f:
            for line in f:
                if separator in line:
                    name, value = line.split(separator)
                    if name.strip() == "IAS_CRT_PATH":
                        ias_crt =  value.strip()
                        return ias_crt

    def get_ias_enable(self):
        separator = "="
        ias_enabled = None
        with open("/opt/BarbiE/env.properties") as f:
            for line in f:
                if separator in line:
                    name, value = line.split(separator)
                    if name.strip() == "IAS_ENABLED":
                        ias_enabled =  value.strip()
                        if ias_enabled == 'True':
                            return True
                        else :
                            return False

    def init_enclave(self, target_lib):
        try:
            p_enclave_id = self.ffi.new("sgx_enclave_id_t *")
            status = target_lib.initialize_enclave(p_enclave_id)
            return p_enclave_id[0]
        except Exception as e:
            LOG.error("Error in initializing enclave!")
            return -1

    def get_crt(self, resp_crt=None):
        pattern = '-----END CERTIFICATE-----\n'
        crt = resp_crt.split(pattern)
        return crt[0]+pattern, crt[1]+"\n"

    def verify_certificate(self, crt=None, cacrt=None):
        try:
            cert = load_certificate(FILETYPE_PEM, crt)
            intermediate_cert = load_certificate(FILETYPE_PEM, cacrt)
            validation_cert = load_certificate(FILETYPE_PEM, cacrt)
            store = X509Store()
            store.add_cert(intermediate_cert)
            store.add_cert(cert)
            store_ctx = X509StoreContext(store, validation_cert)
            if(store_ctx.verify_certificate() == None):
                LOG.info("Certificate verification Passed on Server side")
                return True
            else:
                raise Exception("Certificate Verification Failed on Server side")
        except Exception as e:
            LOG.error(str(e))
            raise Exception("Certificate Validation Failed on Server side", e)

    def verify_signature(self, crt=None, sign=None, resp_body=None):
        try:
            x509 = load_certificate(FILETYPE_PEM, crt)
            pub_key = x509.get_pubkey()
            ias_public_key = dump_publickey(FILETYPE_PEM, pub_key)
            public_key = load_publickey(FILETYPE_PEM, ias_public_key)
            x509 = X509()
            x509.set_pubkey(public_key)
            if verify(x509, base64.b64decode(sign), resp_body, 'sha256') == None:
                LOG.info("Signature verification Passed on Server side")
                return True
        except Exception as e:
            LOG.error(str(e))
            raise Exception("Signature verification Failed on Server side", e)

    def generate_key_pair(self):
        separator = "="
        key_dir = None
        with open("/opt/BarbiE/env.properties") as f:
            for line in f:
                if separator in line:
                    name, value = line.split(separator)
                    if name.strip() == "KEY_PAIR_DIR":
                        key_dir = value.strip()
        pub_key_path = os.path.join(key_dir, "public_key.pem")
        priv_key_path = os.path.join(key_dir, "private_key.pem")
        if not os.path.exists(pub_key_path):
            priv_key = SigningKey.generate(curve=NIST256p)
            pub_key = priv_key.get_verifying_key()
            open(priv_key_path,"w").write(priv_key.to_pem())
            open(pub_key_path,"w").write(pub_key.to_pem())
        else:
            priv_key = SigningKey.from_pem(open(priv_key_path).read())
            pub_key = VerifyingKey.from_pem(open(pub_key_path).read())

        pk64 = pub_key.to_string()
        pk_x, pk_y = pk64[:len(pk64)/2], pk64[len(pk64)/2:]
        hex_priv_key = priv_key.to_string()
        hex_sk = hex_priv_key.encode('hex')

        pk_x = pk_x.encode('hex')
        pk_y = pk_y.encode('hex')
        hex_priv_key_out = [hex_sk[i:i + 2]for i in range(0, len(hex_sk), 2)]
        pk_x_out = [pk_x[i:i + 2] for i in range(0,len(pk_x), 2)]
        pk_y_out = [pk_y[i:i + 2] for i in range(0,len(pk_y), 2)]

        pk_x_out.reverse()
        pk_y_out.reverse()

        pub_key = ""
        for i in range(len(pk_x_out)):
            pub_key = pub_key + pk_x_out[i]
        for i in range(len(pk_y_out)):
            pub_key = pub_key + pk_y_out[i]
        hex_priv_key_out.reverse()
        priv_key = ""
        for i in range(len(hex_priv_key_out)):
            priv_key = priv_key + hex_priv_key_out[i]

        pub_key = base64.b64encode(pub_key + '\0')
        priv_key = base64.b64encode(priv_key + '\0')

        return pub_key , priv_key

    def gen_msg0(self, target_lib, spid=None):
        try:
            if spid is None:
                spid = self.ffi.NULL
            p_ctxt = self.ffi.new("sgx_ra_context_t *")
            p_req0 = self.ffi.new("ra_samp_msg0_request_header_t **")
            ret = target_lib.gen_msg0(p_req0, spid)
            msg0 = base64.b64encode(self.ffi.buffer(p_req0[0]))
            return ret, msg0
        except Exception as e:
            LOG.error("Error in generating msg0")
            raise e

    def proc_msg0(self, target_lib, msg0, spid=None, client_verify_ias=False):
        try:
            if spid is None:
                spid = self.ffi.NULL
            msg0 = self.ffi.from_buffer(base64.b64decode(msg0))
            p_net_ctxt = self.ffi.new("void **")
            status = target_lib.proc_msg0(msg0, p_net_ctxt, spid, client_verify_ias)
            error = self.error_dict[str(status)]
            if(error != 'SP_SPID_SET_ERROR'):
                return status, p_net_ctxt
            else:
                raise Exception("SPID not set server side")
        except Exception as e:
            LOG.error("Error in processing msg0")
            raise e

    def gen_msg1(self, target_lib, enclave_id, pub_key):
        try:
            if pub_key != None:
                pub_key = base64.b64decode(pub_key)
                key = self.ffi.new("char[]", pub_key)
            else:
                key = self.ffi.NULL

            p_ctxt = self.ffi.new("sgx_ra_context_t *")
            p_req1 = self.ffi.new("ra_samp_msg1_request_header_t **")
            target_lib.gen_msg1(enclave_id, p_ctxt, p_req1, key)
            msg1 = base64.b64encode(self.ffi.buffer(p_req1[0]))
            return p_ctxt[0], msg1
        except Exception as e:
            LOG.error("Error in generating msg1")
            raise e

    def proc_msg1_gen_msg2(self, target_lib, msg1, p_net_ctxt, priv_key):
        try:
            if priv_key != None:
                priv_key = base64.b64decode(priv_key)
                key = self.ffi.new("char[]", priv_key)
            else:
                key = self.ffi.NULL

            msg1 = self.ffi.from_buffer(base64.b64decode(msg1))
            pp_resp1 = self.ffi.new("ra_samp_msg1_response_header_t **")
            target_lib.proc_msg1(msg1, p_net_ctxt, pp_resp1, key)
            msg2 = base64.b64encode(self.ffi.buffer(pp_resp1[0]))
            return msg2
        except Exception as e:
            LOG.error("Error in generating msg2")
            raise e

    def proc_msg2_gen_msg3(self, target_lib, enclave_id, msg2, p_ctxt, ias_crt=None, client_verify_ias=False, server_verify_ias=True):
        try:
            if ias_crt is None:
                ias_crt = self.ffi.NULL
            msg2 = self.ffi.from_buffer(base64.b64decode(msg2))
            pp_req2 = self.ffi.new("ra_samp_msg3_request_header_t **")
            resp_crt = self.ffi.new("uint8_t[]", 4000)
            resp_sign = self.ffi.new("uint8_t[]", 500)
            resp_body = self.ffi.new("uint8_t[]", 1200)
            status = target_lib.gen_msg3(enclave_id, p_ctxt, msg2, pp_req2, ias_crt, client_verify_ias, server_verify_ias, resp_crt, resp_sign, resp_body)
            error = self.error_dict[str(status)]
            if(error != 'SP_QUOTE_VERIFICATION_FAILED'):
                msg3 = base64.b64encode(self.ffi.buffer(pp_req2[0]))
            else:
                raise Exception("IAS verification failed")
            return msg3, self.ffi.string(resp_crt), self.ffi.string(resp_sign), self.ffi.string(resp_body)
        except Exception as e:
            LOG.error("Error in generating msg3")
            raise e

    def proc_msg3_gen_msg4(self, target_lib, enclave_id, msg3, p_net_ctxt, sealed_sk, project_id=None, owner_mr_e=None, ias_crt=None, client_verify_ias=False, sealed_key2=None):
        try:
            if ias_crt is None:
                ias_crt = self.ffi.NULL
            owner_mr_e = self.ffi.from_buffer(base64.b64decode(owner_mr_e))
            msg3 = self.ffi.from_buffer(base64.b64decode(msg3))
            if sealed_sk is None:
                sealed_len = 0
                sealed_sk = self.ffi.NULL
            else:
                sealed_len = sealed_sk.length
                sealed_sk = self.ffi.from_buffer(base64.b64decode(sealed_sk.value))
            if project_id is None:
                project_id_len = 0
                project_id = self.ffi.NULL
            else:
                project_id_len = len(project_id)
            sealed_key2_len = sealed_key2.length
            sealed_key2 = self.ffi.from_buffer(base64.b64decode(sealed_key2.value))
            pp_resp2 = self.ffi.new("ra_samp_msg3_response_header_t **")
            target_lib.set_enclave(p_net_ctxt, enclave_id)
            target_lib.set_secret(p_net_ctxt, sealed_sk, sealed_len, sealed_key2, sealed_key2_len)
            status = target_lib.proc_msg3(msg3, p_net_ctxt, pp_resp2, self.ffi.NULL, project_id, owner_mr_e, ias_crt, client_verify_ias)
            #Initially using 177 length of msg4 but
            #after adding project id to msg4 using (209 + project id length) for msg4
            error = self.error_dict[str(status)]
            if(error != 'SP_QUOTE_VERIFICATION_FAILED'):
                msg4 = base64.b64encode(self.ffi.buffer(pp_resp2[0],(417 + project_id_len)))
            else:
                raise Exception("IAS verification failed")
            return msg4
        except Exception as e:
            LOG.error("Error in generating msg4")
            raise e

    def ma_proc_msg4(self, target_lib, enclave_id, s_msg4, s_p_ctxt, c_msg3, c_p_net_ctxt, s_mk, mk_sk, policy_dict, ias_crt, client_verify_ias, project_id_len):
        try:
            plain_sk_len = 16
            b64_iv = 16
            b64_mac = 24
            if s_mk and mk_sk:
                LOG.info("Using existing buffers")
                sealed_len = s_mk.length
                sealed_mk = self.ffi.from_buffer(base64.b64decode(s_mk.value))
                iv = self.ffi.from_buffer(base64.b64decode(mk_sk[:b64_iv]))
                mac = self.ffi.from_buffer(base64.b64decode(mk_sk[b64_iv:(b64_iv + b64_mac)]))
                mk_sk = self.ffi.from_buffer(base64.b64decode(mk_sk[(b64_iv + b64_mac):]))
                mk_sk_len = len(mk_sk)
            else:
                LOG.info("Creating new buffers")
                iv = self.ffi.new("uint8_t[]", self.iv)
                mac = self.ffi.new("uint8_t[]", self.mac)
                mk_sk = self.ffi.new("uint8_t[]", plain_sk_len)
                sealed_len = target_lib.get_sealed_data_len(enclave_id, 0, plain_sk_len)
                sealed_mk = self.ffi.new("uint8_t[]", sealed_len)
                #Set sealed len zero to let native side know this is output variable
                mk_sk_len = plain_sk_len
            if policy_dict:
                policy = policy_dict['policy']
                attribute = policy_dict['attribute']
                iv1 = self.ffi.from_buffer(base64.b64decode(attribute[:b64_iv]))
                mac1 = self.ffi.from_buffer(base64.b64decode(attribute[b64_iv:(b64_iv + b64_mac)]))
                attribute = self.ffi.from_buffer(base64.b64decode(attribute[(b64_iv + b64_mac):]))
                attribute_len = len(attribute)
            else:
                policy = 0
                attribute = self.ffi.NULL
                attribute_len = 0
                iv1 = self.ffi.NULL
                mac1 = self.ffi.NULL

            s_msg4 = self.ffi.from_buffer(base64.b64decode(s_msg4))
            c_msg3 = self.ffi.from_buffer(base64.b64decode(c_msg3))
            pp_resp2 = self.ffi.new("ra_samp_msg3_response_header_t **")
            status = target_lib.ma_proc_ra(enclave_id, s_msg4, s_p_ctxt, c_msg3, c_p_net_ctxt, pp_resp2, sealed_mk, sealed_len, mk_sk, mk_sk_len, iv, mac, ias_crt, client_verify_ias, policy, attribute, attribute_len, iv1, mac1)
            if status == 0:
                c_msg4 = base64.b64encode(self.ffi.buffer(pp_resp2[0],(417 + project_id_len)))
                sealed_mk = base64.b64encode(self.ffi.buffer(sealed_mk))
                mk_sk = base64.b64encode(self.ffi.buffer(iv)) + base64.b64encode(self.ffi.buffer(mac)) + base64.b64encode(self.ffi.buffer(mk_sk))
                sealed_mk_len = target_lib.get_sealed_data_len(enclave_id, 0, plain_sk_len)
                return Secret(sealed_mk, sealed_mk_len), mk_sk, c_msg4
            else:
                raise Exception("Error getting sealed mk and mk_sk")
        except Exception as e:
            LOG.error("Error in ma_proc_msg4")
            raise e

    def proc_msg4(self, target_lib, enclave_id, msg4, p_ctxt, sha2_client, sha2_server):
        try:
            sha2_client =  self.ffi.from_buffer(base64.b64decode(sha2_client))
            sha2_server =  self.ffi.from_buffer(base64.b64decode(sha2_server))
            msg4 = self.ffi.from_buffer(base64.b64decode(msg4))
            plain_sk_len = 16
            secret1_len = target_lib.get_sealed_data_len(enclave_id, 0, plain_sk_len)
            sealed_secret1 = self.ffi.new("uint8_t[]", secret1_len)
            status = target_lib.proc_ra(enclave_id, p_ctxt, msg4, sealed_secret1,
                                        secret1_len, self.ffi.NULL, 0)
            secret1_buf = base64.b64encode(self.ffi.buffer(sealed_secret1))
            target_lib.close_ra(enclave_id, p_ctxt)
            return status, secret1_buf
        except Exception as e:
            LOG.error("Error in prcessing msg4 and retrieving sealed session key")
            raise e

    def new_proc_ra(self, target_lib, enclave_id, msg4, p_ctxt, s_mk, mk_sk):
        try:
            msg4 = self.ffi.from_buffer(base64.b64decode(msg4))
            plain_sk_len = 16
            b64_iv = 16
            b64_mac = 24
            if s_mk and mk_sk:
                LOG.info("Using existing buffers")
                sealed_len = s_mk.length
                sealed_mk = self.ffi.from_buffer(base64.b64decode(s_mk.value))
                iv = self.ffi.from_buffer(base64.b64decode(mk_sk[:b64_iv]))
                mac = self.ffi.from_buffer(base64.b64decode(mk_sk[b64_iv:(b64_iv + b64_mac)]))
                mk_sk = self.ffi.from_buffer(base64.b64decode(mk_sk[(b64_iv + b64_mac):]))
                mk_sk_len = len(mk_sk)
            else:
                LOG.info("Creating new buffers")
                iv = self.ffi.new("uint8_t[]", self.iv)
                mac = self.ffi.new("uint8_t[]", self.mac)
                mk_sk = self.ffi.new("uint8_t[]", plain_sk_len)
                sealed_len = target_lib.get_sealed_data_len(enclave_id, 0, plain_sk_len)
                sealed_mk = self.ffi.new("uint8_t[]", sealed_len)
                #Set sealed len zero to let native side know this is output variable
                sealed_len = 0
                mk_sk_len = 0
            iv1 = self.ffi.new("uint8_t[]", self.iv)
            mac1 = self.ffi.new("uint8_t[]", self.mac)
            dh_sk = self.ffi.new("uint8_t[]", plain_sk_len)
            dh_sk_len = plain_sk_len
            status = target_lib.new_proc_ra(enclave_id, p_ctxt, msg4, sealed_mk, sealed_len, mk_sk, mk_sk_len, iv, mac, dh_sk, dh_sk_len, iv1, mac1)
            if status == 0:
                sealed_mk = base64.b64encode(self.ffi.buffer(sealed_mk))
                mk_sk = base64.b64encode(self.ffi.buffer(iv)) + base64.b64encode(self.ffi.buffer(mac)) + base64.b64encode(self.ffi.buffer(mk_sk))
                dh_sk = base64.b64encode(self.ffi.buffer(iv1)) + base64.b64encode(self.ffi.buffer(mac1)) + base64.b64encode(self.ffi.buffer(dh_sk))
                return Secret(sealed_mk, 576), mk_sk, dh_sk
            else:
                raise Exception("Error getting sealed mk, mk_sk and dh_sk")
        except Exception as e:
            LOG.error("Error in new_proc_ra")
            raise e

    def get_dh_key(self, target_lib, enclave_id, msg4, p_ctxt):
        try:
            msg4 = self.ffi.from_buffer(base64.b64decode(msg4))
            plain_sk_len = 16
            sealed_len = target_lib.get_sealed_data_len(enclave_id, 0, plain_sk_len)
            sealed_dh = self.ffi.new("uint8_t[]", sealed_len)
            status = target_lib.get_dh_key(enclave_id, p_ctxt, msg4, sealed_dh, self.ffi.cast("uint32_t", sealed_len))
            dh_buf = base64.b64encode(self.ffi.buffer(sealed_dh))
            #target_lib.close_ra(enclave_id, p_ctxt)
            return status, dh_buf
        except Exception as e:
            LOG.error("Error in get_dh_key")
            raise e

    def get_project_id(self, target_lib, enclave_id, msg4, p_ctxt):
        try:
            msg4 = self.ffi.from_buffer(base64.b64decode(msg4))
            proj_id_len = self.ffi.cast("uint32_t",0)
            proj_id_len = target_lib.get_project_id_len(enclave_id, p_ctxt, msg4)
            proj_id = self.ffi.new("uint8_t []", proj_id_len)
            status = target_lib.get_project_id(enclave_id, p_ctxt, msg4, proj_id)
            return proj_id, proj_id_len
        except Exception as e:
            LOG.error("Error in geting project id")
            raise e

    def convert_to_python_data(self,project_id=None):
        project_id = self.ffi.string(project_id)
        return project_id

    def get_sk(self, target_lib, p_net_ctx, enc_sk):
        #todo extract iv and mac, call target_lib.get_sk and return plain sk
        try:
            b64_iv = 16
            b64_mac = 24
            iv = self.ffi.from_buffer(base64.b64decode(enc_sk[:b64_iv]))
            mac = self.ffi.from_buffer(base64.b64decode(enc_sk[b64_iv:(b64_iv + b64_mac)]))
            dh_sk = self.ffi.from_buffer(base64.b64decode(enc_sk[(b64_iv + b64_mac):]))
            plain_sk = self.ffi.new("uint8_t[]", 16)
            status = target_lib.get_sk(p_net_ctx, plain_sk, 16, dh_sk, iv, mac)
            return Secret(self.ffi.string(plain_sk, 16), 16)
        except Exception as e:
            LOG.error("Error in get_sk")
            raise e

    def generate_key(self, target_lib, enclave_id, key_len):
        try:
            sealed_len = target_lib.get_sealed_data_len(enclave_id, 0, key_len)
            sealed_key = self.ffi.new("uint8_t[]", sealed_len)
            target_lib.crypto_generate_key(enclave_id, key_len, sealed_key, sealed_len)
            #use these api's to determine required plain text buffer given a sealed buffer
            #add mac always 0 for now
            #add_mac_len = target_lib.get_add_mac_len(enclave_id, sealed_key, sealed_len)
            #plain_len = target_lib.get_encrypted_len(enclave_id, sealed_key, sealed_len)
            return Secret(base64.b64encode(self.ffi.buffer(sealed_key)), sealed_len)
        except Exception as e:
            LOG.error("Error in generating key")
            raise e

    def get_kek(self, target_lib, enclave_id, s_mk, mk_sk, sk_kek, project_id, project_id_len):
        try:
            plain_sk_len = 16
            b64_iv = 16
            b64_mac = 24
            sealed_len = s_mk.length
            sealed_mk = self.ffi.from_buffer(base64.b64decode(s_mk.value))
            iv = self.ffi.from_buffer(base64.b64decode(mk_sk[:b64_iv]))
            mac = self.ffi.from_buffer(base64.b64decode(mk_sk[b64_iv:(b64_iv + b64_mac)]))
            mk_sk = self.ffi.from_buffer(base64.b64decode(mk_sk[(b64_iv + b64_mac):]))
            mk_sk_len = plain_sk_len

            iv1 = self.ffi.from_buffer(base64.b64decode(sk_kek[:b64_iv]))
            mac1 = self.ffi.from_buffer(base64.b64decode(sk_kek[b64_iv:(b64_iv + b64_mac)]))
            sk_kek = self.ffi.from_buffer(base64.b64decode(sk_kek[(b64_iv + b64_mac):]))
            sk_kek_len = plain_sk_len

            sealed_kek_len = target_lib.get_sealed_data_len(enclave_id, 0, plain_sk_len)
            sealed_kek = self.ffi.new("uint8_t[]", sealed_kek_len)

            status = target_lib.get_kek(enclave_id, sealed_mk, sealed_len, mk_sk, mk_sk_len, iv, mac, sk_kek, sk_kek_len, iv1, mac1, sealed_kek, sealed_kek_len, project_id, project_id_len)
            if status != 0:
                raise Exception("Error in getting sealed kek")
            return Secret(base64.b64encode(self.ffi.buffer(sealed_kek)), sealed_len)
        except Exception as e:
            LOG.error("Error in getting sealed kek")
            raise e

    def secret_encrypt(self, target_lib, enclave_id, s_mk, mk_sk, sk_secret, project_id, project_id_len):
        try:
            plain_sk_len = 16
            b64_iv = 16
            b64_mac = 24
            sealed_len = s_mk.length
            sealed_mk = self.ffi.from_buffer(base64.b64decode(s_mk.value))
            iv = self.ffi.from_buffer(base64.b64decode(mk_sk[:b64_iv]))
            mac = self.ffi.from_buffer(base64.b64decode(mk_sk[b64_iv:(b64_iv + b64_mac)]))
            mk_sk = self.ffi.from_buffer(base64.b64decode(mk_sk[(b64_iv + b64_mac):]))
            mk_sk_len = plain_sk_len

            iv1 = self.ffi.from_buffer(base64.b64decode(sk_secret[:b64_iv]))
            mac1 = self.ffi.from_buffer(base64.b64decode(sk_secret[b64_iv:(b64_iv + b64_mac)]))
            sk_secret = self.ffi.from_buffer(base64.b64decode(sk_secret[(b64_iv + b64_mac):]))
            sk_secret_len = len(sk_secret)

            mk_secret = self.ffi.new("uint8_t[]", sk_secret_len)
            iv2 = self.ffi.new("uint8_t[]", self.iv)
            mac2 = self.ffi.new("uint8_t[]", self.mac)

            status = target_lib.secret_encrypt(enclave_id, sealed_mk, sealed_len, mk_sk, mk_sk_len, iv, mac, sk_secret, sk_secret_len, iv1, mac1, mk_secret, sk_secret_len, iv2, mac2, project_id, project_id_len)
            if status != 0:
                raise Exception("Error in getting mk encrypted secret")
            return base64.b64encode(self.ffi.buffer(iv2)) + base64.b64encode(self.ffi.buffer(mac2)) + base64.b64encode(self.ffi.buffer(mk_secret))
        except Exception as e:
            LOG.error("Error in getting mk encrypted secret")
            raise e

    def secret_decrypt(self, target_lib, enclave_id, s_mk, mk_sk, mk_secret, project_id, project_id_len):
        try:
            plain_sk_len = 16
            b64_iv = 16
            b64_mac = 24
            sealed_len = s_mk.length
            sealed_mk = self.ffi.from_buffer(base64.b64decode(s_mk.value))
            iv = self.ffi.from_buffer(base64.b64decode(mk_sk[:b64_iv]))
            mac = self.ffi.from_buffer(base64.b64decode(mk_sk[b64_iv:(b64_iv + b64_mac)]))
            mk_sk = self.ffi.from_buffer(base64.b64decode(mk_sk[(b64_iv + b64_mac):]))
            mk_sk_len = plain_sk_len

            iv1 = self.ffi.from_buffer(base64.b64decode(mk_secret[:b64_iv]))
            mac1 = self.ffi.from_buffer(base64.b64decode(mk_secret[b64_iv:(b64_iv + b64_mac)]))
            mk_secret = self.ffi.from_buffer(base64.b64decode(mk_secret[(b64_iv + b64_mac):]))
            mk_secret_len = len(mk_secret)

            sk_secret = self.ffi.new("uint8_t[]", mk_secret_len)
            iv2 = self.ffi.new("uint8_t[]", self.iv)
            mac2 = self.ffi.new("uint8_t[]", self.mac)

            status = target_lib.secret_decrypt(enclave_id, sealed_mk, sealed_len, mk_sk, mk_sk_len, iv, mac, mk_secret, mk_secret_len, iv1, mac1, sk_secret, mk_secret_len, iv2, mac2, project_id, project_id_len)
            if status != 0:
                raise Exception("Error in getting sk encrypted secret")
            return base64.b64encode(self.ffi.buffer(iv2)) + base64.b64encode(self.ffi.buffer(mac2)) + base64.b64encode(self.ffi.buffer(sk_secret))
        except Exception as e:
            LOG.error("Error in getting sk encrypted secret")
            raise e

    def provision_kek(self, target_lib, enclave_id, sealed_sk, sk_kek, project_id=None):
        try:
            if project_id is None:
                project_id = self.ffi.NULL
                proj_id_len = 0
            else:
                proj_id_len = len(project_id)
            b64_iv = 16
            b64_mac = 24
            sealed_len = sealed_sk.length
            sealed_sk = self.ffi.from_buffer(base64.b64decode(sealed_sk.value))
            iv = self.ffi.from_buffer(base64.b64decode(sk_kek[:b64_iv]))
            mac = self.ffi.from_buffer(base64.b64decode(sk_kek[b64_iv:(b64_iv + b64_mac)]))
            sk_kek = self.ffi.from_buffer(base64.b64decode(sk_kek[(b64_iv + b64_mac):]))
            plain_kek_len = len(sk_kek)
            sealed_kek_len = target_lib.get_sealed_data_len(enclave_id, 0, plain_kek_len)
            sealed_kek = self.ffi.new("uint8_t[]", sealed_kek_len)
            status = target_lib.crypto_provision_kek(enclave_id, sealed_sk, sealed_len, sk_kek, plain_kek_len, iv, mac, sealed_kek, sealed_kek_len, project_id, proj_id_len)
            if status != 0:
                raise Exception("Error in decrypting secret")
            return base64.b64encode(self.ffi.buffer(sealed_kek))
        except Exception as e:
            LOG.error("Error in provisioning of kek")
            raise e

    def legacy_encrypt(self, target_lib, plain_sk, secret):
        try:
            iv = self.ffi.new("uint8_t[]", self.iv)
            mac = self.ffi.new("uint8_t[]", self.mac)
            enc_secret = self.ffi.new("uint8_t[]", secret.length)
            target_lib.crypto_legacy_encrypt(plain_sk.value, plain_sk.length, secret.value, secret.length, enc_secret, iv, mac)
            return base64.b64encode(self.ffi.buffer(iv)) + base64.b64encode(self.ffi.buffer(mac)) + base64.b64encode(self.ffi.buffer(enc_secret))
        except Exception as e:
            LOG.error("ERROR: Encryption of the secret failed!")
            raise e

    def encrypt(self, target_lib, enclave_id, sealed_sk, secret):
        try:
            iv = self.ffi.new("uint8_t[]", self.iv)
            mac = self.ffi.new("uint8_t[]", self.mac)
            sealed_len = sealed_sk.length
            sealed_sk = self.ffi.from_buffer(base64.b64decode(sealed_sk.value))
            enc_secret = self.ffi.new("uint8_t[]", secret.length)
            target_lib.crypto_encrypt(enclave_id, sealed_sk, sealed_len, secret.value, secret.length, enc_secret, iv, mac)
            return base64.b64encode(self.ffi.buffer(iv)) + base64.b64encode(self.ffi.buffer(mac)) + base64.b64encode(self.ffi.buffer(enc_secret))
        except Exception as e:
            LOG.error("ERROR: Encryption of the secret failed!")
            raise e

    def decrypt(self, target_lib, enclave_id, sealed_sk, enc_secret):
        try:
            b64_iv = 16
            b64_mac = 24
            iv = self.ffi.from_buffer(base64.b64decode(enc_secret[:b64_iv]))
            mac = self.ffi.from_buffer(base64.b64decode(enc_secret[b64_iv:(b64_iv + b64_mac)]))
            enc_secret = self.ffi.from_buffer(base64.b64decode(enc_secret[(b64_iv + b64_mac):]))
            length = len(enc_secret)
            sealed_len = sealed_sk.length
            sealed_sk = self.ffi.from_buffer(base64.b64decode(sealed_sk.value))
            secret = self.ffi.new("uint8_t[]", length)
            target_lib.crypto_decrypt(enclave_id, sealed_sk, sealed_len, secret, length, enc_secret, iv, mac, self.ffi.NULL, 0)
            return base64.b64encode(self.ffi.buffer(secret))
        except Exception as e:
            LOG.error("ERROR: Decryption of the secret failed!")
            raise e

    def transport(self, target_lib, enclave_id, sealed_kek, sealed_sk, project_id=None):
        try:
            if project_id is None:
                project_id = self.ffi.NULL
                proj_id_len = 0
            else:
                proj_id_len = len(project_id)
            iv = self.ffi.new("uint8_t[]", self.iv)
            mac = self.ffi.new("uint8_t[]", self.mac)
            sealed_kek_len = sealed_kek.length
            sealed_kek = self.ffi.from_buffer(base64.b64decode(sealed_kek.value))
            sealed_sk_len = sealed_sk.length
            sealed_sk = self.ffi.from_buffer(base64.b64decode(sealed_sk.value))
            sk_len = target_lib.get_encrypted_len(enclave_id, sealed_sk, sealed_sk_len)
            kek_sk = self.ffi.new("uint8_t[]", sk_len)
            target_lib.crypto_transport_secret(enclave_id, sealed_kek, sealed_kek_len, sealed_sk, sealed_sk_len, kek_sk, sk_len, iv, mac, project_id, proj_id_len)
            return base64.b64encode(self.ffi.buffer(iv)) + base64.b64encode(self.ffi.buffer(mac)) + base64.b64encode(self.ffi.buffer(kek_sk))
        except Exception as e:
            LOG.error("Error in transporting the secret")
            raise e

    #no need for target lib, server action only
    def kek_encrypt(self, enclave_id, kek_sk, sealed_kek, sk_secret, project_id=None):
        try:
            if project_id is None:
                project_id = self.ffi.NULL
                proj_id_len = 0
            else:
                proj_id_len = len(project_id)
            b64_iv = 16
            b64_mac = 24
            iv1 = self.ffi.from_buffer(base64.b64decode(kek_sk[:b64_iv]))
            mac1 = self.ffi.from_buffer(base64.b64decode(kek_sk[b64_iv:(b64_iv + b64_mac)]))
            kek_sk = self.ffi.from_buffer(base64.b64decode(kek_sk[(b64_iv + b64_mac):]))
            sealed_kek_len = sealed_kek.length
            sealed_kek = self.ffi.from_buffer(base64.b64decode(sealed_kek.value))
            iv = self.ffi.from_buffer(base64.b64decode(sk_secret[:b64_iv]))
            mac = self.ffi.from_buffer(base64.b64decode(sk_secret[b64_iv:(b64_iv + b64_mac)]))
            sk_secret = self.ffi.from_buffer(base64.b64decode(sk_secret[(b64_iv + b64_mac):]))
            length = len(sk_secret)
            kek_secret = self.ffi.new("uint8_t[]", length)
            self.barbie_s.crypto_store_secret(enclave_id, kek_sk, len(kek_sk), iv1, mac1, sealed_kek, sealed_kek_len, sk_secret, length, kek_secret, length, iv, mac, str(project_id), proj_id_len)
            return base64.b64encode(self.ffi.buffer(iv)) + base64.b64encode(self.ffi.buffer(mac)) + base64.b64encode(self.ffi.buffer(kek_secret))
        except Exception as e:
            LOG.error("Error in encrypting the secret with kek")
            raise e

    #no need for target lib, server action only
    def kek_decrypt(self, enclave_id, kek_sk, sealed_kek, kek_secret, project_id=None):
        try:
            if project_id is None:
                project_id = self.ffi.NULL
                proj_id_len = 0
            else:
                proj_id_len = len(project_id)
            b64_iv = 16
            b64_mac = 24
            iv1 = self.ffi.from_buffer(base64.b64decode(kek_sk[:b64_iv]))
            mac1 = self.ffi.from_buffer(base64.b64decode(kek_sk[b64_iv:(b64_iv + b64_mac)]))
            kek_sk = self.ffi.from_buffer(base64.b64decode(kek_sk[(b64_iv + b64_mac):]))
            sealed_kek_len = sealed_kek.length
            sealed_kek = self.ffi.from_buffer(base64.b64decode(sealed_kek.value))
            iv = self.ffi.from_buffer(base64.b64decode(kek_secret[:b64_iv]))
            mac = self.ffi.from_buffer(base64.b64decode(kek_secret[b64_iv:(b64_iv + b64_mac)]))
            kek_secret = self.ffi.from_buffer(base64.b64decode(kek_secret[(b64_iv + b64_mac):]))
            length = len(kek_secret)
            sk_secret = self.ffi.new("uint8_t[]", length)
            self.barbie_s.crypto_get_secret(enclave_id, kek_sk, len(kek_sk), iv1, mac1, sealed_kek, sealed_kek_len, kek_secret, length, sk_secret, length, iv, mac, str(project_id), proj_id_len)
            return base64.b64encode(self.ffi.buffer(iv)) + base64.b64encode(self.ffi.buffer(mac)) + base64.b64encode(self.ffi.buffer(sk_secret))
        except Exception as e:
            LOG.error("Error in decrypting the secret with kek")
            raise e

    def get_mk_mr_list(self, target_lib, enclave_id, mk_sk, sealed_mk, sk_mr_list, project_id, project_id_len, mk_mr_list=None):
        try:
            b64_iv = 16
            b64_mac = 24
            iv1 = self.ffi.from_buffer(base64.b64decode(mk_sk[:b64_iv]))
            mac1 = self.ffi.from_buffer(base64.b64decode(mk_sk[b64_iv:(b64_iv + b64_mac)]))
            mk_sk = self.ffi.from_buffer(base64.b64decode(mk_sk[(b64_iv + b64_mac):]))
            sealed_mk_len = sealed_mk.length
            sealed_mk = self.ffi.from_buffer(base64.b64decode(sealed_mk.value))
            iv2 = self.ffi.from_buffer(base64.b64decode(sk_mr_list[:b64_iv]))
            mac2 = self.ffi.from_buffer(base64.b64decode(sk_mr_list[b64_iv:(b64_iv + b64_mac)]))
            sk_mr_list = self.ffi.from_buffer(base64.b64decode(sk_mr_list[(b64_iv + b64_mac):]))
            iv = self.ffi.new("uint8_t[]", self.iv)
            mac = self.ffi.new("uint8_t[]", self.mac)
            if mk_mr_list is None:
                mk_mr_list = self.ffi.NULL
                iv3 = self.ffi.NULL
                mac3 = self.ffi.NULL
                mk_mr_list_len = 0
            else:
                iv3 = self.ffi.from_buffer(base64.b64decode(mk_mr_list[:b64_iv]))
                mac3 = self.ffi.from_buffer(base64.b64decode(mk_mr_list[b64_iv:(b64_iv + b64_mac)]))
                mk_mr_list = self.ffi.from_buffer(base64.b64decode(mk_mr_list[(b64_iv + b64_mac):]))
                mk_mr_list_len = len(mk_mr_list)
            new_mk_mr_list = self.ffi.new("uint8_t[]", len(sk_mr_list))
            sk_mr_list_len = len(sk_mr_list)
            target_lib.get_mk_mr_list(enclave_id, sealed_mk, sealed_mk_len, mk_sk, sk_mr_list, sk_mr_list_len, project_id, len(project_id), mk_mr_list, mk_mr_list_len, new_mk_mr_list, iv1, mac1, iv2, mac2, iv3, mac3, iv, mac)

            return base64.b64encode(self.ffi.buffer(iv)) + base64.b64encode(self.ffi.buffer(mac)) + base64.b64encode(self.ffi.buffer(new_mk_mr_list))
        except Exception as e:
            LOG.error("Error generating mk_mr_list" + e)
            raise e

    def get_sk_data(self, target_lib, enclave_id, mk_sk, sealed_mk, mk_data, project_id, project_id_len):
        try:
            b64_iv = 16
            b64_mac = 24
            iv1 = self.ffi.from_buffer(base64.b64decode(mk_sk[:b64_iv]))
            mac1 = self.ffi.from_buffer(base64.b64decode(mk_sk[b64_iv:(b64_iv + b64_mac)]))
            mk_sk = self.ffi.from_buffer(base64.b64decode(mk_sk[(b64_iv + b64_mac):]))
            sealed_mk_len = sealed_mk.length
            sealed_mk = self.ffi.from_buffer(base64.b64decode(sealed_mk.value))
            iv2 = self.ffi.from_buffer(base64.b64decode(mk_data[:b64_iv]))
            mac2 = self.ffi.from_buffer(base64.b64decode(mk_data[b64_iv:(b64_iv + b64_mac)]))
            mk_data = self.ffi.from_buffer(base64.b64decode(mk_data[(b64_iv + b64_mac):]))
            mk_data_len = len(mk_data)
            iv = self.ffi.new("uint8_t[]", self.iv)
            mac = self.ffi.new("uint8_t[]", self.mac)
            sk_data = self.ffi.new("uint8_t[]", len(mk_data))
            target_lib.get_sk_data(enclave_id, sealed_mk, sealed_mk_len, mk_sk, mk_data, mk_data_len, project_id, len(project_id), sk_data, iv1, mac1, iv2, mac2, iv, mac)

            return base64.b64encode(self.ffi.buffer(iv)) + base64.b64encode(self.ffi.buffer(mac)) + base64.b64encode(self.ffi.buffer(sk_data))
        except Exception as e:
            LOG.error("Error generating sk_data" + e)
            raise e

    def compare_secret(self, target_lib, secret1, secret2, secret_len):
        try:
            secret1 = self.ffi.from_buffer(base64.b64decode(secret1))
            secret2 = self.ffi.from_buffer(base64.b64decode(secret2))
            if target_lib.crypto_cmp(secret1, secret2, secret_len) == 0:
                return True
            return False
        except Exception as e:
            LOG.error("Error in comparing the secrets")
            raise e

    def compare_sealed_secret(self, target_lib, encalve_id, secret1, secret2):
        try:
            secret1 = self.ffi.from_buffer(base64.b64decode(secret1))
            secret2 = self.ffi.from_buffer(base64.b64decode(secret2))
            if target_lib.crypto_sealed_cmp(encalve_id, secret1, len(secret1), secret2, len(secret2)) == 0:
                return True
            return False
        except Exception as e:
            raise Exception("Error in comparing the sealed secrets", e)

    def destroy_enclave(self, target_lib, enclave_id):
        try:
            target_lib.destroy_enclave(enclave_id)
        except Exception as e:
            LOG.error("Error in destroying enclave!")
            #raise e

    def write_buffer_to_file(self, filename, buff):
        try:
            dir_path = os.path.dirname(os.path.realpath(__file__))
            write_file = os.path.join(dir_path, filename)
            with open(write_file, 'w') as f:
                f.write(buff)
        except Exception as e:
            LOG.error("Error writing buffer to file!")
            raise e

    def read_buffer_from_file(self, filename):
        try:
            dir_path = os.path.dirname(os.path.realpath(__file__))
            read_file = os.path.join(dir_path, filename)
            if os.path.exists(os.path.join(dir_path, read_file)):
                with open(read_file, 'r') as f:
                    read_buffer = f.read()
                    return read_buffer
        except Exception as e:
            LOG.error("Error reading buffer from file!")
            raise e

    def get_mr_enclave(self, msg3):
        try:
            msg3 = self.ffi.from_buffer(base64.b64decode(msg3))
            mr_e = self.barbie_s.get_mr_e(msg3)
            #return self.ffi.string(mr_e)
            #return self.ffi.buffer(mr_e)
            return base64.b64encode(self.ffi.buffer(mr_e, 32))
        except Exception as e:
            LOG.error("Error in retrieveing mr enclave")
            raise e

    def get_mr_signer(self, msg3):
        try:
            msg3 = self.ffi.from_buffer(base64.b64decode(msg3))
            mr_s = self.barbie_s.get_mr_s(msg3)
            #return self.ffi.string(mr_s)
            #return self.ffi.buffer(mr_s)
            return base64.b64encode(self.ffi.buffer(mr_s, 32))
        except Exception as e:
            LOG.error("Error in retrieveing mr signer")
            raise e

    def get_report_sha256(self, target_lib, msg3):
        try:
            msg3 = self.ffi.from_buffer(base64.b64decode(msg3))
            sha256 = self.ffi.new("uint8_t []", 32)
            target_lib.get_report_sha256(msg3, sha256)
            return base64.b64encode(self.ffi.buffer(sha256))
        except Exception as e:
            LOG.error("Error in calculating SHA256")
            raise e

    def test_legacy_client(self):
        try:

            #plain_secret = "my-private-secre"
            secret = "This-Is-My-Private-Secret"
            plain_secret = Secret(secret, len(secret))

            enclave_id = self.init_enclave(self.barbie_s)

            #To simulate KEK of server side
            sealed_kek = self.generate_key(self.barbie_s, enclave_id, 16)

            enc_secret = self.encrypt(self.barbie_s, enclave_id, sealed_kek, plain_secret)

            r_secret = self.decrypt(self.barbie_s, enclave_id, sealed_kek, enc_secret)
            r_secret = base64.b64decode(r_secret)

            if r_secret == secret:
                print "Legacy Client : Secret Management done!"
            else:
                print "Legacy Client : Secret Management failed!"

        finally:
            self.destroy_enclave(self.barbie_s, enclave_id)


    def test_sgx_client_wo_sgx_hw(self, spid=None, crt_path=None):
        try:
            s_eid = self.init_enclave(self.barbie_s)

            plain_sk = Secret("", len(""))

            #Perform attestation
            ret, msg0 = self.gen_msg0(self.barbie_s, spid)

            p_ctxt, msg1 = self.gen_msg1(self.barbie_s, s_eid)
            print "gen_msg1 returned: " + msg1

            ret, p_net_ctxt = self.proc_msg0(self.barbie_c, msg0, spid, False)
            msg2 = self.proc_msg1_gen_msg2(self.barbie_c, msg1, p_net_ctxt)
            print "send_msg1_recv_msg2 returned: " + msg2

            msg3, crt, sig, resp_body = self.proc_msg2_gen_msg3(self.barbie_s, s_eid, msg2, p_ctxt, crt_path, False)
            print "proc_msg2_gen_msg3 returned: " + msg3

            msg4 = self.legacy_proc_msg3_gen_msg4(self.barbie_c, msg3, p_net_ctxt, plain_sk , "sgx_wo_hw", crt_path, False)
            print "send_msg3_recv_msg4 returned: " + str(msg4)

            status, s_dh = self.get_dh_key(self.barbie_s, s_eid, msg4, p_ctxt)
            print "get_dh_key returned: " + str(status)

            proj_id, proj_id_len = self.get_project_id(self.barbie_s, s_eid, msg4, p_ctxt)

            s_sk = self.generate_key(self.barbie_s, s_eid, 16)
            plain_kek_len = 16
            sealed_len = self.barbie_s.get_sealed_data_len( s_eid, 0, plain_kek_len)
            dh_sk = self.transport(self.barbie_s, s_eid, Secret(s_dh, sealed_len), s_sk ,None)
            plain_sk = self.get_sk(self.barbie_c, p_net_ctxt, dh_sk)
            #status, plain_sk = self.get_sk(self.barbie_c, p_net_ctxt, 16, dh_sk)
            #status, sk = self.proc_msg4(self.barbie_s, s_eid, msg4, p_ctxt)
            #sealed_sk = Secret(sk, sealed_len)

            #Perform kek provisioning
            kek = "yek etyb neetxis"
            plain_kek = Secret(kek, len(kek))

            sk_kek = self.legacy_encrypt(self.barbie_c, plain_sk, plain_kek)

            kek = self.provision_kek(self.barbie_s, s_eid, s_sk, sk_kek, None)
            plain_kek_len = 16
            sealed_len = self.barbie_s.get_sealed_data_len(s_eid, 0, plain_kek_len)
            sealed_kek = Secret(kek, sealed_len)

            kek_sk = self.transport(self.barbie_c, s_eid, sealed_kek, s_sk, proj_id)

            #Perform secret management
            secret = "my-private-secret"
            plain_secret = Secret(secret, len(secret))

            sk_secret = self.legacy_encrypt(self.barbie_c, plain_sk, plain_secret)

            kek_secret = self.kek_encrypt(s_eid, kek_sk, sealed_kek, sk_secret, "sgx_wo_hw")

            rec = self.kek_decrypt(s_eid, kek_sk, sealed_kek, kek_secret, "sgx_wo_hw")

            if self.compare_secret(self.barbie_c, rec[40:], sk_secret[40:], plain_secret.length):
                print "SGX Aware Client Without SGX hardware : Secret Management done!"
            else:
                print "SGX Aware Cliwnt Without SGX hardware : Secret Management failed!"

        finally:
            self.destroy_enclave(self.barbie_s, s_eid)

if __name__ == "__main__":
    obj = SGXInterface()
    if len(sys.argv) < 3:
        print "please provide SPID and path of certificate"
        sys.exit()
    obj.init_env_variables()
    SPID = sys.argv[1]
    CRT_PATH = sys.argv[2]
    print "---------------------------------------SGX Aware Client Without SGX hardware(START)-------------------------------------------"
    obj.test_sgx_client_wo_sgx_hw(SPID, CRT_PATH)
    print "----------------------------------------SGX Aware Client Without SGX hardware(END)--------------------------------------------"
    print "--------------------------------------------------Legacy Client(START)--------------------------------------------------------"
    obj.test_legacy_client()
    print "---------------------------------------------------Legacy Client(END)---------------------------------------------------------"
