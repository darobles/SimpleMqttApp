/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cl.drobles.mqtt.subscribers;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.MqttCallback;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttClientPersistence;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.eclipse.paho.client.mqttv3.persist.MqttDefaultFilePersistence;

/**
 *
 * @author Daniel
 */
public class MQTTSubscriber implements MqttCallback {

    private String broker = "";
    MqttClient client;
    String clientId = "";
    String topic = "";
    String caFilePath;
    String clientCrtFilePath;
    String clientKeyFilePath;
    String mqttUserName;
    String mqttPassword;
    String tmp_path = "";
    boolean isSSL = false;

    public MQTTSubscriber(String broker, String topic, String caFilePath, String clientCrtFilePath, String clientKeyFilePath, String mqttUserName, String mqttPassword, String tmp_path) {
        this.broker = broker;
        this.topic = topic;
        this.caFilePath = caFilePath;
        this.clientCrtFilePath = clientCrtFilePath;
        this.clientKeyFilePath = clientKeyFilePath;
        this.mqttUserName = mqttUserName;
        this.mqttPassword = mqttPassword;
        this.tmp_path = tmp_path;
    }

    @Override
    public void connectionLost(Throwable thrwbl) {
        this.doSuscripcion();
    }

    @Override
    public void messageArrived(String string, MqttMessage mm) {
        if(isSSL)
            Logger.getLogger(MQTTSubscriber.class.getName()).log(Level.INFO, "New Message SSL to [" + topic + "] : {0} ",  mm.toString());
        else
            Logger.getLogger(MQTTSubscriber.class.getName()).log(Level.INFO, "New Message No-SSL to [" + topic + "] : {0} ",  mm.toString());
    }

    @Override
    public void deliveryComplete(IMqttDeliveryToken imdt) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    public void doSuscripcion() {
        try {
            clientId = MqttClient.generateClientId();
            MqttClientPersistence clientPersistence = new MqttDefaultFilePersistence(tmp_path);
            client = new MqttClient(broker, MqttClient.generateClientId(), clientPersistence);
            MqttConnectOptions connOpts = new MqttConnectOptions();
            connOpts.setCleanSession(true);
            if (mqttUserName != null && !mqttUserName.equals("")) {
                connOpts.setUserName(mqttUserName);
            }
            if (mqttPassword != null && !mqttPassword.equals("")) {
                connOpts.setPassword(mqttPassword.toCharArray());
            }
            connOpts.setConnectionTimeout(60);
            connOpts.setKeepAliveInterval(60);
            connOpts.setMqttVersion(MqttConnectOptions.MQTT_VERSION_3_1);
            if (broker.toUpperCase().startsWith("SSL")) {
                isSSL = true;
                SSLSocketFactory socketFactory = getSocketFactory(caFilePath,
                        clientCrtFilePath, clientKeyFilePath, "");
                connOpts.setSocketFactory(socketFactory);
            }
            client.connect(connOpts);
            client.setCallback(this);
            client.subscribe(topic);
            Logger.getLogger(MQTTSubscriber.class.getName()).log(Level.INFO, "[Mqtt]:  Subscribed to : {0}", topic);

        } catch (MqttException e) {
            Logger.getLogger(MQTTSubscriber.class.getName()).log(Level.SEVERE, null, e.toString());
            try {
                client.disconnect();
            } catch (MqttException e2) {
            }
            Logger.getLogger(MQTTSubscriber.class.getName()).log(Level.INFO, "[Mqtt]: Desconectado");
        } catch (Exception ex) {
            Logger.getLogger(MQTTSubscriber.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static SSLSocketFactory getSocketFactory(final String caCrtFile,
            final String crtFile, final String keyFile, final String password)
            throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // load CA certificate
        X509Certificate caCert = null;

        FileInputStream fis = new FileInputStream(caCrtFile);
        BufferedInputStream bis = new BufferedInputStream(fis);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        while (bis.available() > 0) {
            caCert = (X509Certificate) cf.generateCertificate(bis);
        }

        // load client certificate
        bis = new BufferedInputStream(new FileInputStream(crtFile));
        X509Certificate cert = null;
        while (bis.available() > 0) {
            cert = (X509Certificate) cf.generateCertificate(bis);
        }

        // load client private key
        PEMParser pemParser = new PEMParser(new FileReader(keyFile));
        Object object = pemParser.readObject();
        PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder()
                .build(password.toCharArray());
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter()
                .setProvider("BC");
        KeyPair key;
        if (object instanceof PEMEncryptedKeyPair) {
            key = converter.getKeyPair(((PEMEncryptedKeyPair) object)
                    .decryptKeyPair(decProv));
        } else {
            key = converter.getKeyPair((PEMKeyPair) object);
        }
        pemParser.close();

        // CA certificate is used to authenticate server
        KeyStore caKs = KeyStore.getInstance(KeyStore.getDefaultType());
        caKs.load(null, null);
        caKs.setCertificateEntry("ca-certificate", caCert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509");
        tmf.init(caKs);

        // client key and certificates are sent to server so it can authenticate
        // us
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setCertificateEntry("certificate", cert);
        ks.setKeyEntry("private-key", key.getPrivate(), password.toCharArray(),
                new java.security.cert.Certificate[]{cert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory
                .getDefaultAlgorithm());
        kmf.init(ks, password.toCharArray());

        // finally, create SSL socket factory
        SSLContext context = SSLContext.getInstance("TLSv1.2");
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        return context.getSocketFactory();
    }
}
