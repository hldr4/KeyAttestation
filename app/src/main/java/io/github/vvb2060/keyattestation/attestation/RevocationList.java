package io.github.vvb2060.keyattestation.attestation;

import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;

import io.github.vvb2060.keyattestation.AppApplication;

public record RevocationList(String status, String reason) {
    private static final JSONObject data = getStatus();

    private static JSONObject getStatus() {
        try {
            URL url = new URL("https://android.googleapis.com/attestation/status");

            HttpURLConnection con = (HttpURLConnection) url.openConnection();

            con.setRequestMethod("GET");

            con.setRequestProperty("Content-Type", "application/json");

            StringBuilder response = new StringBuilder();

            String inputLine;
            try (BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
            }

            con.disconnect();

            return new JSONObject(response.toString());

        } catch (Throwable t) {
            Log.e(AppApplication.TAG, "getStatus", t);
        }
        return null;
    }

    public static RevocationList get(BigInteger serialNumber) {
        String serialNumberString = serialNumber.toString(16).toLowerCase();
        JSONObject revocationStatus;
        try {
            revocationStatus = data.getJSONObject(serialNumberString);
        } catch (JSONException e) {
            return null;
        }
        try {
            var status = revocationStatus.getString("status");
            var reason = revocationStatus.getString("reason");
            return new RevocationList(status, reason);
        } catch (JSONException e) {
            return new RevocationList("", "");
        }
    }

    @Override
    public String toString() {
        return "status is " + status + ", reason is " + reason;
    }
}
