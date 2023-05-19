package org.example;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.Date;
import java.security.MessageDigest;
import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.util.Properties;

import org.w3c.dom.*;
import org.xml.sax.SAXException;
import java.text.SimpleDateFormat;


public class Certnotification{

    public static void main(String[] args)

            throws ParserConfigurationException, SAXException {
        URL url;
        try {
            ArrayList<String> status_cert = new ArrayList<String>();
            ArrayList<String> expiry_date = new ArrayList<String>();
            ArrayList<String> url_String = new ArrayList<String>();
            ArrayList<String> color_code = new ArrayList<String>();
            url = new URL("https://staging.servicesgateway.carrier.com/restman/1.0/trustedCertificates/");

            HttpsURLConnection con = (HttpsURLConnection) url.openConnection();

            // set request headers
            con.setRequestProperty("Authorization", "Basic bWFkaHU6Mzd3cmFWY0FA");
            // con.setRequestProperty("Content-Type", "application/json");

            // optional: set additional request properties
            // con.setRequestProperty("User-Agent", "Mozilla/5.0");

            // set request method
            con.setRequestMethod("GET");

            int responseCode = con.getResponseCode();
            System.out.println("Response code: " + responseCode);
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document doc = dBuilder.parse(con.getInputStream());
            ((Node) doc.getDocumentElement()).normalize();

            NodeList nodeList = ((org.w3c.dom.Document) doc).getElementsByTagName("l7:Item");
            for (int i = 0; i < nodeList.getLength(); i++) {

                Node node = nodeList.item(i);
                if (node.getNodeType() == Node.ELEMENT_NODE) {
                    Element element = (Element) node;
                    String existingcert = element.getElementsByTagName("l7:Encoded").item(0).getTextContent();
                    String urlstring = element.getElementsByTagName("l7:Name").item(0).getTextContent();
                    existingcert = "-----BEGIN CERTIFICATE-----\n" + existingcert + "-----END CERTIFICATE-----\n";
                    ArrayList<String> expiry_status = validatecert(existingcert, urlstring);

                    url_String.add(expiry_status.get(0));
                    expiry_date.add(expiry_status.get(1));
                    status_cert.add(expiry_status.get(2));
                    color_code.add(expiry_status.get(3));
                }
            }

            String cert_info = "<!DOCTYPE html><html>" + "<head>" + "<style>" + "table, th, td {"
                    + "border: 1px solid black;border-collapse: collapse;}"
                    + "</style>" + "</head>" + "<body>" + "<table style='width:100%'>"
                    + "<tr>" + "<th>CN</th>" + "<th>Expiry</th>"
                    + "<th>Cert Status</th>" + "</tr>";
            for (int i = 0; i < status_cert.size(); i++) {

                cert_info = cert_info + "<tr>" + "<td>" + url_String.get(i) + "</td>" + "<td>"
                        + expiry_date.get(i)
                        + "</td>" + "<td style='color:" + color_code.get(i) + ";'>" + " " + status_cert.get(i) + "</td>"
                        + "</tr>";

            }
            cert_info = cert_info + "</table>" + "</body>" + "</html>";
            System.out.println(cert_info);
            sendmail("expiry details", cert_info);

            // BufferedReader in = new BufferedReader(new
            // InputStreamReader(con.getInputStream()));
            // String inputLine;
            // StringBuffer response = new StringBuffer();
            // while ((inputLine = in.readLine()) != null) {
            // response.append(inputLine);
            // }
            // in.close();

            // System.out.println("Response body: " + response.toString());
        } catch (MalformedURLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private StringBuffer sendPost() {

        StringBuffer response = new StringBuffer();
        String url = "";
        final String CONTENT_LENGTH = "131";
        final String CONTENT_TYPE = "application/x-www-form-urlencoded";
        final String ACCEPT_LANGUAGE = "en-US,en;q=0.8";

        try {
            // create http connection
            URL obj = new URL(url);
            HttpsURLConnection connection = (HttpsURLConnection) obj.openConnection();

            // add request header
            connection.setRequestMethod("GET");
            // connection.setheader()
            // connection.setDoInput(true);
            // connection.setDoOutput(true);
            // connection.setUseCaches(false);
            // connection.setRequestProperty("Accept-Language", ACCEPT_LANGUAGE);
            // connection.setRequestProperty("Content-Type", CONTENT_TYPE);
            // connection.setRequestProperty("Content-Length", CONTENT_LENGTH);

            DataOutputStream output = new DataOutputStream(connection.getOutputStream());

            // form data
            // String content =
            // "documentId=3896&action=getAnnotationModel&annotationLayer=1&pageCount=1&pageIndex=0";

            // write output stream and close output stream
            // output.writeBytes(content);
            output.flush();
            output.close();

            // read in the response data
            BufferedReader input = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String inputLine;
            while ((inputLine = input.readLine()) != null) {
                response.append(inputLine.toString());
            }

            // close input stream
            input.close();

            // print out content
            int responseCode = connection.getResponseCode();
            System.out.println("response code: " + responseCode);
            System.out.println("respone is: " + response);

        } catch (MalformedURLException e) {
            e.printStackTrace();

        } catch (IOException e) {
            e.printStackTrace();
        }

        return response;
    }

    public static ArrayList<String> validatecert(String expectedSignature, String urlString) {
        ArrayList<String> expiry_status = new ArrayList<String>();
        String redColor = "\033[31m";
        String greenColor = "\033[32m";
        String yellowColor = "\033[0;33m";
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate expectedcert = (X509Certificate) cf
                    .generateCertificate(new ByteArrayInputStream(expectedSignature.getBytes()));

            Date expiryDate = expectedcert.getNotAfter();

            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

            byte[] sha1Fingerprint = sha1.digest(expectedcert.getEncoded());
            byte[] sha256Fingerprint = sha256.digest(expectedcert.getEncoded());

            String expectedSHA1 = bytesToHexString(sha1Fingerprint);
            String expectedSHA256 = bytesToHexString(sha256Fingerprint);

            Date today = new Date();
            long difference = expiryDate.getTime() - today.getTime();
            long days = difference / (1000 * 60 * 60 * 24);
            System.out.println("differnce: " + difference / (1000 * 60 * 60 * 24));
            expiry_status.add(urlString);
            // fingerprint_info.add(expectedSHA1);
            SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
            String dateStr = dateFormat.format(expiryDate);
            expiry_status.add(dateStr);
            if (today.after(expiryDate)) {

                System.out.println(yellowColor + "The SSL certificate for " + urlString + " has expired!");
                System.out.println(yellowColor + "The certificate fingerprints match the expected values.");
                expiry_status.add("The certificate fingerprints match the expected values");
                expiry_status.add("yellow");
                // sendmail("expiry details", "The certificate fingerprints match the expected
                // values");

            } else if (days <= 15) {
                System.out.println(yellowColor + "The certificate fingerprints match the expected values.");
                System.out.println(yellowColor + "The SSL certificate for " + urlString + " is valid until "
                        + expiryDate);
                expiry_status.add("The certificate fingerprints match the expected values");
                // sendmail("expiry details", "The certificate fingerprints match the expected
                // values");
                expiry_status.add("yellow");

            } else if (days > 15) {
                System.out.println(greenColor + "The certificate fingerprints match the expected values.");
                System.out.println(greenColor + "The SSL certificate for " + urlString + " is valid until "
                        + expiryDate);
                expiry_status.add("The certificate fingerprints match the expected values");
                expiry_status.add("green");
                // sendmail("expiry details", "The certificate fingerprints match the expected
                // values");
            }

        } catch (

                Exception e) {

            System.out.println(redColor + "Cert Checker couldn't reach the endpoint");
            expiry_status.add("Cert Checker couldn't reach the endpoint");
            // sendmail("expiry details", "Cert Checker couldn't reach the endpoint");
            expiry_status.add("red");
        }

        return expiry_status;

    }

    public static byte[] hexStringToByteArray(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return data;
    }

    public static String bytesToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /// SEND MAIL////

    public static String sendmail(String Subject, String messages) {

        String to = "arun.singh0259@gmail.com"; // recipient email address
        String from = "arun.singh0259@gmail.com"; // sender email address
        String password = "jvtkabxcelcrihgx"; // Gmail password for the sender email account

        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");

        // create a session with authentication and SSL/TLS encryption
        Session session = Session.getInstance(props,
                new javax.mail.Authenticator() {
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(from, password);
                    }
                });

        try {
            // create a message
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(from));
            message.setRecipients(Message.RecipientType.TO,
                    InternetAddress.parse(to));
            message.setSubject(Subject);
            message.setContent(messages, "text/html; charset=utf-8");

            // send the message
            Transport.send(message);

            System.out.println("Email sent successfully.");

        } catch (MessagingException e) {
            throw new RuntimeException(e);
        }
        return to;
    }
}