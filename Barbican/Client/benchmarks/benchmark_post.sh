#!/bin/bash

if [ $# -lt 4 ]; then
    echo 'Invalid command'
    echo 'Usage : ./benchmark_post <ip> <users> <requests> <concurrency> [sgx_enabled]'
    echo 'ip            : IPv4 address of the server'
    echo 'users         : Numeber of users'
    echo 'requests      : Number of requets per user'
    echo 'concurrency   : Concurrency of each user'
    echo 'sgx_enabled   : Reperesnts if sgx based barbican or not'
    exit
fi

if [ $5 ]; then
    i=1
    key="sixteen byte key"
    while [ $i -lt $(($2 + 1)) ]
    do
        #Do attestation for users
        id=$i$i$i$i$i
        python ../sgx_client.py $id $key
        i=$(($i + 1))
    done
fi

i=1
while [ $i -lt $(($2 + 1)) ]
do
    id=$i$i$i$i$i
    #Run benchmark in parallel
    if [ $5 ]; then
        ab -n $3 -c $4 -p post_enc.data -T "application/json" -H "X-Project-Id:$id" https://$1:443/v2/secrets 1>user$i.log &
    else
        ab -n $3 -c $4 -p post_plain.data -T "application/json" -H "X-Project-Id:$id" https://$1:443/v1/secrets 1>legacy_user$i.log &
    fi
    i=$(($i + 1))
done
