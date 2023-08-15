/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package cl.drobles.main;

import cl.drobles.mqtt.publisher.MqttPublisher;
import cl.drobles.mqtt.subscribers.MQTTSubscriber;

/**
 *
 * @author drobles
 */
public class SimpleMqtt {


    public static void main(String[] args) {

        /* we use server's certificates to make a SSL connection */
        String caFilePath = "resources/certs/mosquitto.org.crt";
        String clientCrtFilePath = "resources/certs/client.crt";
        String clientKeyFilePath = "resources/certs/client.key";
        String mqttUserName = "ro";
        String mqttPassword = "readonly";
        String topic = "my_topic";
        String enc_broker = "ssl://test.mosquitto.org:8885"; //encrypted broker
        String unenc_broker = "tcp://test.mosquitto.org:1884"; // unencyped broker
        String tmp_path = "/tmp/tmp_path"; //to store tmp files

        /* Subscription to unsecure protocol using ssl certificates and authentication*/
        MQTTSubscriber mqttSubscriber = new MQTTSubscriber(unenc_broker, topic, caFilePath, clientCrtFilePath, clientKeyFilePath, mqttUserName, mqttPassword, tmp_path);
        mqttSubscriber.doSuscripcion();

         /* Subscription to secure protocol using ssl certificates and authentication*/
        MQTTSubscriber mqttSubscriberSSL = new MQTTSubscriber(enc_broker, topic, caFilePath, clientCrtFilePath, clientKeyFilePath, mqttUserName, mqttPassword, tmp_path);
        mqttSubscriberSSL.doSuscripcion();
        
        String message = "Hello, I'm Daniel";
        MqttPublisher mqttPublisher = new MqttPublisher(enc_broker, mqttUserName, mqttPassword, caFilePath, clientCrtFilePath, clientKeyFilePath, tmp_path);
        mqttPublisher.publishCommand(topic, message);
        mqttPublisher.disconnect();
    }

    public void callDimac() {

    }
}
