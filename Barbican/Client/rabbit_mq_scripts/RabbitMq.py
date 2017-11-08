import pika

r_body = None
class RabbitMq():

    def __init__(self):
        credentials = self.init_env_variables()
        self.credentials = pika.PlainCredentials(credentials['username'], 
                                                   credentials['password'])
        self.params = pika.ConnectionParameters(credentials['host'], 
                                                 int(credentials['port']), 
                                                  credentials['virtual_host'], 
                                                  self.credentials)
        self.connection = pika.BlockingConnection(self.params)
        self.channel = self.connection.channel()

    #Function to publish message using RabbitMq 
    def publish(self, msg, queue_name):
        self.channel.queue_declare(queue = queue_name)
        self.channel.basic_publish(exchange='',
                      routing_key=queue_name,
                      body=msg)

    def callback(self, ch, method, properties, body):
        ch.stop_consuming()
        global r_body
        r_body = body

    #Function to Receive message using RabbitMq
    def receive(self, queue_name):
        self.channel.queue_declare(queue = queue_name)
        self.channel.basic_consume(self.callback,
                      queue=queue_name,no_ack=True)
        self.channel.start_consuming()
        global r_body
        return r_body

    #Function Return dictionary required to logging to RabbitMq server
    def init_env_variables(self):
        separator = "="
        cred = {}
        with open("/opt/BarbiE/rabbit_mq.properties") as f:
            for line in f:
                if separator in line:
                    name, value = line.split(separator)
                    cred[name.strip()] = value.strip()
        return cred

if __name__ == "__main__":
    rbc=RabbitMq()
    rbc.publish('hello world','hello')
    bdy = rbc.receive('hello')
    print "message recived : " + bdy 
