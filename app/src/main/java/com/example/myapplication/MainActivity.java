package com.example.myapplication;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.provider.Settings;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.Toast;
import android.util.Log;
import java.io.OutputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executor;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import com.bumptech.glide.Glide;
import com.journeyapps.barcodescanner.ScanContract;
import com.journeyapps.barcodescanner.ScanIntentResult;
import com.journeyapps.barcodescanner.ScanOptions;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import java.security.KeyStore;
import java.nio.charset.StandardCharsets;

public class MainActivity extends AppCompatActivity {
    private static String hashedEmail;
    private BiometricPrompt biometricPrompt;
    private BiometricPrompt.PromptInfo promptInfo;

    private String socketiocode;

    private String orgName;
    private String adminName;
    private String deviceid;
    private boolean isFingerprintAuthenticated;
    private String modeoflogin;

    private String authToken="data";


    private String databasestoresendstring;

    private final ActivityResultLauncher<ScanOptions> barcodeLauncher = registerForActivityResult(
            new ScanContract(), this::handleQRCodeResult);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        String email = "user@example.com";
        ImageView gifImageView = findViewById(R.id.windowsLogo);
        Glide.with(this).asGif().load(R.drawable.encryption).into(gifImageView);
        Button btnClearPreferences = findViewById(R.id.btnClearPreferences);
        Button btnscanner = findViewById(R.id.btnscannner);

        btnClearPreferences.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {

                clearSharedPreferences();
                clearKeyStore();
            }

        });
        btnscanner.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                initializeBiometricPrompt();
                authenticateUser();
            }

        });


    }

    private void initializeBiometricPrompt() {
        Executor executor = ContextCompat.getMainExecutor(this);

        biometricPrompt = new BiometricPrompt(this, executor, new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                Toast.makeText(MainActivity.this, "Authentication succeeded!", Toast.LENGTH_SHORT).show();
                startQRCodeScan();
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                Toast.makeText(MainActivity.this, "Authentication failed. Try again.", Toast.LENGTH_SHORT).show();
            }

            @Override
            public void onAuthenticationError(int errorCode, CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                Toast.makeText(MainActivity.this, "Authentication error: " + errString, Toast.LENGTH_SHORT).show();
            }
        });
        promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setTitle("Biometric Authentication")
                .setSubtitle("Use your fingerprint to authenticate")
                .setNegativeButtonText("Cancel")
                .build();
    }

    private void authenticateUser() {
        biometricPrompt.authenticate(promptInfo);
    }

    private void startQRCodeScan() {
        ScanOptions options = new ScanOptions();
        options.setOrientationLocked(true);
        barcodeLauncher.launch(options);
    }

    private void clearKeyStore() {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            String keyAlias = "emailKey";

            if (keyStore.containsAlias(keyAlias)) {
                keyStore.deleteEntry(keyAlias);
                Log.d("Keystore", "Key removed successfully.");
            } else {
                Log.d("Keystore", "No key found with the alias.");
            }
        } catch (Exception e) {
            Log.e("Keystore", "Error clearing Keystore: " + e.getMessage());
        }
    }

    private void handleQRCodeResult(ScanIntentResult result) {
        if (result.getContents() != null) {
            String scannedEmail = result.getContents();
            Toast.makeText(MainActivity.this, "string" + scannedEmail, Toast.LENGTH_LONG).show();
            String[] parts = scannedEmail.split("\\+");
            orgName = parts[0]; // First part
            adminName = parts[1]; // Second part
            String signin = parts[2]; // Third part
            socketiocode=parts[3];
            modeoflogin=parts[4];
            Log.d("ActivityCheck", socketiocode);
            Toast.makeText(MainActivity.this, socketiocode+"socketiocode", Toast.LENGTH_LONG).show();


            if (signin.equals("signup")) {
                Toast.makeText(MainActivity.this, "Signup MODE", Toast.LENGTH_LONG).show();

                try {
                    KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                    keyStore.load(null);
                    if (keyStore.containsAlias("emailKey")){
                        Toast.makeText(this, "Already Registered", Toast.LENGTH_SHORT).show();
                    }
                    else {


                        generateKey();
                        hashedEmail = hashEmailWithKeystore(adminName);
                        storeHashedEmailInSharedPreferences(hashedEmail);
                        Toast.makeText(this, "Email hashed and stored", Toast.LENGTH_SHORT).show();
                        Toast.makeText(this, "Keystore value: " + adminName + " " + hashedEmail, Toast.LENGTH_SHORT).show();
                        Log.d("ActivityCheck", "handleqrcoderesult called the sendauthtobackendfunction");
                        sendAuthTokenToBackend1();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            } else if (signin.equals("logout")) {
                Log.d("ActivityCheck", "Entered in to the logout section ");


                try {
                    if (verifyEmail(adminName)) {
                        Log.d("ActivityCheck", "email verified we can logout the user such called the method");
                        sendAuthTokenToBackend3();

                        Toast.makeText(this, "successfully made request for logut!", Toast.LENGTH_SHORT).show();
                    } else {
                        Toast.makeText(this, "Failed to send request to backedn for logout", Toast.LENGTH_SHORT).show();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }


            }
            else{
                Toast.makeText(this, "Signin MODE", Toast.LENGTH_LONG).show();
                try {
                    if (verifyEmail(adminName)) {
                        sendAuthTokenToBackend2();

                        Toast.makeText(this, "Email verified successfully!", Toast.LENGTH_SHORT).show();
                    } else {
                        Toast.makeText(this, "Email verification failed!", Toast.LENGTH_SHORT).show();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            deviceid="temporary";

            isFingerprintAuthenticated = true;


            Log.d("AuthToken", "Authentication Token: " + authToken);

            Toast.makeText(MainActivity.this, "Auth Token: " + authToken, Toast.LENGTH_LONG).show();

        }
    }
    public void clearSharedPreferences() {
        Toast.makeText(MainActivity.this, "Cleared Preferences", Toast.LENGTH_SHORT).show();
        SharedPreferences sharedPreferences = getSharedPreferences("userPrefs", MODE_PRIVATE);
        SharedPreferences.Editor editor = sharedPreferences.edit();
        editor.clear(); // Clears all data
        editor.apply(); // Apply changes asynchronously
        Log.d("SharedPreferences", "All SharedPreferences data cleared.");
    }


    public void generateKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        if (!keyStore.containsAlias("emailKey")) {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore");
            keyGenerator.init(new KeyGenParameterSpec.Builder("emailKey", KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build());
            keyGenerator.generateKey();
        }
    }
    // Master Admin, Manager, User


    public String hashEmailWithKeystore(String email) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        SecretKey key = (SecretKey) keyStore.getKey("emailKey", null);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);

        byte[] emailBytes = email.getBytes(StandardCharsets.UTF_8);
        byte[] hashedBytes = mac.doFinal(emailBytes);

        return Base64.encodeToString(hashedBytes, Base64.NO_PADDING);
    }

    public boolean verifyEmail(String enteredEmail) throws Exception {
        String enteredHash = hashEmailWithKeystore(enteredEmail);
        String storedHash = getHashedEmailFromSharedPreferences();
        if (enteredHash != null && storedHash != null) {
            boolean holder=((enteredHash.trim()).equals(storedHash.trim()));

            return holder;
        }
        return false;
    }


    private void storeHashedEmailInSharedPreferences(String hashedEmail) {
        Log.d("HashedEmail", "Saving hashed email: " + hashedEmail);  // Log for saved email
        SharedPreferences sharedPreferences = getSharedPreferences("userPrefs", MODE_PRIVATE);
        SharedPreferences.Editor editor = sharedPreferences.edit();
        editor.putString("hashedEmail", hashedEmail);
        editor.apply();
    }
    private String getHashedEmailFromSharedPreferences() {
        SharedPreferences sharedPreferences = getSharedPreferences("userPrefs", MODE_PRIVATE);


        String storedHashedEmail = sharedPreferences.getString("hashedEmail", null);
        hashedEmail=storedHashedEmail.trim();
        deviceid="temporary";
        Log.d("HashedEmail", "Retrieved stored hashed email: " + storedHashedEmail);
        return storedHashedEmail;
    }


    private void sendAuthTokenToBackend1() {
        Log.d("ActivityCheck", "startofauthtokentobackend");
        new Thread(() -> {
            Log.d("ActivityCheck", "new thread started");
            try {
                runOnUiThread(() -> Log.d("ActivityCheck", authToken));

                URL url = new URL("https://ad-api-backend.vercel.app/userenrollment?safetystring="
                        + hashedEmail.trim() + "&orgName=" + orgName
                        + "&deviceid=" + deviceid
                        + "&isFingerprintauthenticated=" + isFingerprintAuthenticated
                        + "&adminname=" + adminName
                        + "&socketiocode="+socketiocode
                        + "&modeoflogin="+modeoflogin

                );

                runOnUiThread(() -> Log.d("ActivityCheck", url.toString()));

                HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
                urlConnection.setRequestMethod("POST");
                urlConnection.setDoInput(true);
                runOnUiThread(() -> Log.d("ActivityCheck", "Conenction Established Sending Request"));

                int responseCode = urlConnection.getResponseCode();
                runOnUiThread(() -> Log.d("ActivityCheck", "responsecode"+responseCode));

                if (responseCode == HttpURLConnection.HTTP_OK) {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
                    StringBuilder response = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        response.append(line);
                    }
                    reader.close();
                    runOnUiThread(() -> Log.d("ActivityCheck", "Response message from backend"+response.toString()));
                } else {
                    runOnUiThread(() -> Log.d("ActivityCheck", "Error sending authtoken to backend"+responseCode));
                }

                urlConnection.disconnect();
                runOnUiThread(() -> Toast.makeText(this, "connection closed", Toast.LENGTH_SHORT).show());
            } catch (Exception e) {
                runOnUiThread(() -> Toast.makeText(getApplicationContext(), "Error sending auth token: " + e.getMessage(), Toast.LENGTH_SHORT).show());
            }
        }).start();
    }
    private void sendAuthTokenToBackend2() {
        Log.d("ActivityCheck", "startofauthtokentobackend");
        new Thread(() -> {
            Log.d("ActivityCheck", "new thread started");
            try {
                runOnUiThread(() -> Log.d("ActivityCheck", authToken));

                URL url = new URL("https://ad-api-backend.vercel.app/userverification?safetystring="
                        + hashedEmail + "&orgName=" + orgName
                        + "&deviceid=" + deviceid
                        + "&isFingerprintauthenticated=" + isFingerprintAuthenticated
                        + "&adminname=" + adminName
                        + "&socketiocode="+socketiocode
                        + "&modeoflogin="+modeoflogin
                );

                runOnUiThread(() -> Log.d("ActivityCheck", url.toString()));
                HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
                urlConnection.setRequestMethod("POST");
                urlConnection.setDoInput(true);

                runOnUiThread(() -> Log.d("ActivityCheck", "Conenction Established Sending Request"));

                int responseCode = urlConnection.getResponseCode();
                runOnUiThread(() -> Log.d("ActivityCheck", "responsecode"+responseCode));

                if (responseCode == HttpURLConnection.HTTP_OK) {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
                    StringBuilder response = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        response.append(line);
                    }
                    reader.close();
                    runOnUiThread(() -> Log.d("ActivityCheck", "Response message from backend"+response.toString()));
                } else {
                    runOnUiThread(() -> Log.d("ActivityCheck", "Error sending authtoken to backend"+responseCode));
                }

                urlConnection.disconnect();
                runOnUiThread(() -> Toast.makeText(this, "connection closed", Toast.LENGTH_SHORT).show());
            } catch (Exception e) {
                runOnUiThread(() -> Toast.makeText(getApplicationContext(), "Error sending auth token: " + e.getMessage(), Toast.LENGTH_SHORT).show());
            }
        }).start();
    }





    private void sendAuthTokenToBackend3() {
        Log.d("ActivityCheck", "entry point of logout to backend code");
        new Thread(() -> {
            Log.d("ActivityCheck", "new thread started");
            try {
                runOnUiThread(() -> Log.d("ActivityCheck", authToken));

                URL url = new URL("https://ad-api-backend.vercel.app/logoutprocessandroid?safetystring="
                        + hashedEmail + "&orgName=" + orgName
                        + "&deviceid=" + deviceid
                        + "&isFingerprintauthenticated=" + isFingerprintAuthenticated
                        + "&adminname=" + adminName
                        + "&socketiocode="+socketiocode
                        + "&modeoflogin="+modeoflogin
                );

                runOnUiThread(() -> Log.d("ActivityCheck", url.toString()));
                HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
                urlConnection.setRequestMethod("POST");
                urlConnection.setDoInput(true);

                runOnUiThread(() -> Log.d("ActivityCheck", "Conenction Established Sending Request logout"));

                int responseCode = urlConnection.getResponseCode();
                runOnUiThread(() -> Log.d("ActivityCheck", "responsecode logout"+responseCode));

                if (responseCode == HttpURLConnection.HTTP_OK) {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
                    StringBuilder response = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        response.append(line);
                    }
                    reader.close();
                    runOnUiThread(() -> Log.d("ActivityCheck", "Response message from backend"+response.toString()));
                } else {
                    runOnUiThread(() -> Log.d("ActivityCheck", "Error sending authtoken to backend"+responseCode));
                }

                urlConnection.disconnect();
                runOnUiThread(() -> Toast.makeText(this, "connection closed", Toast.LENGTH_SHORT).show());
            } catch (Exception e) {
                runOnUiThread(() -> Toast.makeText(getApplicationContext(), "Error sending auth token: " + e.getMessage(), Toast.LENGTH_SHORT).show());
            }
        }).start();
    }


}
