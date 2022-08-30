package com.example.fido_j;

import static android.content.Context.MODE_PRIVATE;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.util.Base64;
import android.util.Log;

import kotlin.text.Charsets;

public class PreferenceData {
    private Context context;
    private SharedPreferences preferences;
    private SharedPreferences.Editor editor;

    private String id,authenticatorData,clientDataJSON,signature,keyHandle,type,username,userHandle;
    public PreferenceData(Context context){
        this.context=context;
    }
    public byte[] getId() {
        preferences= context.getSharedPreferences("Save",MODE_PRIVATE);
        id=preferences.getString("id","");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            return Base64.decode(id,Base64.URL_SAFE);
        }
        else{
            return null;
        }
    }

    public void setId(String Id) {
        preferences= context.getSharedPreferences("Save",MODE_PRIVATE);
        editor=preferences.edit();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            editor.putString("id", Id);
            editor.commit();
        }
    }

    public byte[] getAuthenticatorData() {
        preferences= context.getSharedPreferences("Save",MODE_PRIVATE);
        authenticatorData=preferences.getString("authenticatorData","");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            return Base64.decode(authenticatorData,Base64.DEFAULT);
        }
        else{
            return null;
        }
    }

    public void setAuthenticatorData(byte[] authenticatorData) {
        preferences= context.getSharedPreferences("Save",MODE_PRIVATE);
        editor=preferences.edit();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            editor.putString("authenticatorData", Base64.encodeToString(authenticatorData,Base64.DEFAULT));
            editor.commit();
        }
    }

    public byte[] getClientDataJSON() {
        preferences= context.getSharedPreferences("Save",MODE_PRIVATE);
        clientDataJSON=preferences.getString("clientDataJSON","");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            return Base64.decode(clientDataJSON,Base64.DEFAULT);
        }
        else{
            return null;
        }
    }

    public void setClientDataJSON(byte[] clientDataJSON) {
        preferences= context.getSharedPreferences("Save",MODE_PRIVATE);
        editor=preferences.edit();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            editor.putString("clientDataJSON", Base64.encodeToString(clientDataJSON,Base64.DEFAULT));
            editor.commit();
        }
    }

    public void setClientDataStringRevise(String clientDataString){
        preferences= context.getSharedPreferences("Save",MODE_PRIVATE);
        editor=preferences.edit();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            editor.putString("clientDataString", clientDataString);
            editor.commit();
        }
    }

    public String getClientDataStringRevise(){
        preferences= context.getSharedPreferences("Save",MODE_PRIVATE);
        return preferences.getString("clientDataString", "");

    }


    public byte[] getSignature() {
        preferences= context.getSharedPreferences("Save",MODE_PRIVATE);
        signature=preferences.getString("signature","");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            return java.util.Base64.getUrlDecoder().decode(signature);
//            return Base64.decode(signature,Base64.DEFAULT);
        }
        else{
            return null;
        }
    }

    public void setSignature(byte[] signature) {
        preferences= context.getSharedPreferences("Save",MODE_PRIVATE);
        editor=preferences.edit();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            editor.putString("signature", Base64.encodeToString(signature,Base64.URL_SAFE).replace("\n",""));
            editor.commit();
        }
    }

    public byte[] loadKeyHandle(){
        preferences= context.getSharedPreferences("Save",MODE_PRIVATE);
        keyHandle=preferences.getString("keyHandle","");
        Log.e("TAG", "loadKeyHandle ads: "+keyHandle);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            return java.util.Base64.getUrlDecoder().decode(keyHandle);
        }
        else{
            return null;
        }
    }

    public void saveKeyHandle(byte[] keyHandle){
        preferences= context.getSharedPreferences("Save",MODE_PRIVATE);
        editor=preferences.edit();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            editor.putString("keyHandle", java.util.Base64.getUrlEncoder().encodeToString(keyHandle));
            editor.commit();
        }
    }

    public String getUsername() {
        preferences= context.getSharedPreferences("Save",MODE_PRIVATE);
        username = preferences.getString("Username","");
        return type;
    }

    public void setUsername(String username) {
        preferences= context.getSharedPreferences("Save",MODE_PRIVATE);
        editor=preferences.edit();
        editor.putString("Username", username);
        editor.commit();
    }

    public void saveSignGetInResult(String result){
        preferences= context.getSharedPreferences("Save",MODE_PRIVATE);
        editor=preferences.edit();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            editor.putString("signGetInResult", result);
            editor.commit();
        }
    }

    public String getSignGetInResult() {
        preferences = context.getSharedPreferences("Save", MODE_PRIVATE);
        return preferences.getString("signGetInResult", "");
    }

    // user id
    public void setUserId(String userId){
        preferences= context.getSharedPreferences("Save",MODE_PRIVATE);
        editor=preferences.edit();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            editor.putString("userId", userId);
            editor.commit();
        }
    }

    public String getUserId(){
        preferences = context.getSharedPreferences("Save", MODE_PRIVATE);
        return preferences.getString("userId", "");
    }
}
