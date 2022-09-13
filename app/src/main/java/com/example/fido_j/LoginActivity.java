package com.example.fido_j;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.databinding.DataBindingUtil;

import com.example.fido_j.api.AuthApi;
import com.example.fido_j.credentials.CredentialsActivity;
import com.example.fido_j.databinding.ActivityLoginBinding;
import com.example.fido_j.username.MainActivity;
import com.google.android.gms.fido.Fido;
import com.google.android.gms.fido.fido2.Fido2ApiClient;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAssertionResponse;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorErrorResponse;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredential;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRequestOptions;
import com.google.android.gms.tasks.OnSuccessListener;
import com.google.android.gms.tasks.Task;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import kotlin.text.Charsets;

public class LoginActivity extends AppCompatActivity {
    private ActivityLoginBinding binding;
    private AuthApi api=new AuthApi();
    private int REQUEST_CODE_REGISTER =1;
    private int AUTH_ACTIVITY_RES_5=5;
    private PreferenceData storeHandle;
    private String publicKey,credId;
    private PublicKeyCredentialRequestOptions requestOptions;
    private Task<PendingIntent> fido2PendingIntent;
    private Activity activity;
    private Context context;
    private List<String> list = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
//        setContentView(R.layout.activity_register);

        binding= DataBindingUtil.setContentView(this, R.layout.activity_login);
        activity=this;
        storeHandle= new PreferenceData(getApplicationContext());
        context=getApplicationContext();

        binding.btnRegist.setOnClickListener(view->{
            Intent intent = new Intent(LoginActivity.this, MainActivity.class);
            startActivity(intent);
        });

        binding.btnNext.setOnClickListener(view->{
            String username = binding.etUsername.getText().toString();
            // 打get 成功的話打驗證
            if(!"".equals(username)) {
                api.sigInOptionRequest(context, new AuthApi.SignOptionGet() {
                    @Override
                    public void SignOptionGetSuccess(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,String result) {
                        requestOptions=publicKeyCredentialRequestOptions;
                        PreferenceData preferenceData = new PreferenceData(context);
                        preferenceData.saveSignGetInResult(result);
                        Fido2ApiClient fido2ApiClient = Fido.getFido2ApiClient(getApplicationContext());
                        fido2PendingIntent = fido2ApiClient.getSignPendingIntent(requestOptions);
                        fido2PendingIntent.addOnSuccessListener(new OnSuccessListener<PendingIntent>() {
                            @Override
                            public void onSuccess(PendingIntent pendingIntent) {
                                new Thread(new Runnable() {
                                    @Override
                                    public void run() {
                                        try {
                                            Log.d("IntentSenderrrrr",""+pendingIntent.getIntentSender().toString());
                                            activity.startIntentSenderForResult(
                                                    pendingIntent.getIntentSender(),
                                                    2,
                                                    null, // fillInIntent,
                                                    0, // flagsMask,
                                                    0, // flagsValue,
                                                    0); //extraFlags);
                                        } catch (Exception e) {
                                            Log.d("LOGTAG", "" + e.getMessage());
                                        }
                                    }
                                }).start();
                            }
                        });
                    }

                    @Override
                    public void SignOptionGetFail(String msg) {

                    }
                });
            }
        });
    }
    //驗證跳轉頁面完成後跳此函數
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        Log.d("RequestOptions",""+data.hasExtra(Fido.FIDO2_KEY_RESPONSE_EXTRA)+"\n"
        +data.hasExtra(Fido.FIDO2_KEY_CREDENTIAL_EXTRA)+"\n"
        +data.hasExtra(Fido.FIDO2_KEY_ERROR_EXTRA)+"\n"
        +data.hasExtra(Fido.KEY_RESPONSE_EXTRA));
        if (resultCode == RESULT_OK) {
            PublicKeyCredential credential = PublicKeyCredential.deserializeFromBytes(data.getByteArrayExtra(Fido.FIDO2_KEY_CREDENTIAL_EXTRA));
//            Log.d("Credentialllll",""+credential.getResponse());
            if (data.hasExtra(Fido.FIDO2_KEY_RESPONSE_EXTRA)) {
                byte[] fido2Response = data.getByteArrayExtra(Fido.FIDO2_KEY_RESPONSE_EXTRA);
                Log.d("Response Extra",""+fido2Response);
                if(requestCode==2){
                    try {
                        handleSignResponse(fido2Response);
                    } catch (JSONException | UnsupportedEncodingException | CborException e) {
                        e.printStackTrace();
                    }
                }
            }
            else if (data.hasExtra(Fido.FIDO2_KEY_ERROR_EXTRA)){
                handleErrorResponse(data.getByteArrayExtra(Fido.FIDO2_KEY_ERROR_EXTRA));
            }
        }
    }
    //處理驗證畫面產生錯誤的回傳
    private void handleErrorResponse(byte[] errorBytes) {
        AuthenticatorErrorResponse authenticatorErrorResponse = AuthenticatorErrorResponse.deserializeFromBytes(errorBytes);
        String errorName = authenticatorErrorResponse.getErrorCode().name();
        String errorMessage = authenticatorErrorResponse.getErrorMessage();
        Log.e("LOG_TAG", "errorCode.name:"+errorName);
        Log.e("LOG_TAG", "errorMessage:"+errorMessage);
        Toast.makeText(getApplicationContext(),errorMessage,Toast.LENGTH_SHORT).show();
    }
    //處理驗證畫面成功的回傳
    private void handleSignResponse(byte[] fido2Response) throws JSONException, UnsupportedEncodingException, CborException {
        AuthenticatorAssertionResponse response = AuthenticatorAssertionResponse.deserializeFromBytes(fido2Response);
        Log.e("TAG", "handleSignResponse 看: "+new String(response.getClientDataJSON(), Charsets.UTF_8));
        JSONObject clientDataJsonRevise = new JSONObject(new String(response.getClientDataJSON(), Charsets.UTF_8));
//        clientDataJsonRevise.put("origin",AuthApi.BASE_URL);
//        clientDataJsonRevise.remove("androidPackageName");
//        clientDataJsonRevise.put("crossOrigin",false);
//        clientDataJsonRevise.put("crossOrigin",false);
        String keyHandleBase64 = Base64.encodeToString(response.getKeyHandle(), Base64.URL_SAFE);
        String clientDataJson = new String(response.getClientDataJSON(), Charsets.UTF_8);
        String authenticatorDataBase64 = Base64.encodeToString(response.getAuthenticatorData(), Base64.URL_SAFE);
        String signatureBase64 = Base64.encodeToString(response.getSignature(), Base64.URL_SAFE);
        String userHandle64 = Base64.encodeToString(response.getKeyHandle(),Base64.NO_WRAP);

        storeHandle.setAuthenticatorData(response.getAuthenticatorData());
        storeHandle.setSignature(response.getSignature());
        storeHandle.setClientDataJSON(response.getClientDataJSON());

//        String clientDataString = storeHandle.getClientDataStringRevise();
        //有解碼問題
        String clientDataJsonReviseString = Base64.encodeToString(clientDataJsonRevise.toString().getBytes("utf-8"),Base64.NO_WRAP);
        Log.e("TAG", "handleSignResponse 改: "+clientDataJsonReviseString );
//        storeHandle.setUserHandle(response.getUserHandle()); //null
        //有差不能刪
        authenticatorDataBase64 = authenticatorDataBase64.replace("\n","").replace("=","");
        keyHandleBase64 = keyHandleBase64.replace("\n","").replace("=","");
        clientDataJson = clientDataJson.replace("\n","").replace("=","");
        signatureBase64 = signatureBase64.replace("\n","").replace("=","");
        Log.d("LOG_TAGg", "userHandleBase64:"+response.getUserHandle());
        Log.d("LOG_TAGg", "keyHandleBase64:"+keyHandleBase64);
        Log.d("LOG_TAGg", "clientDataJSON:"+clientDataJson);
        Log.d("LOG_TAGg", "authenticatorDataBase64:"+authenticatorDataBase64);
        Log.d("LOG_TAGg", "signatureBase64:"+signatureBase64);
        Log.e("LOG_TAGg", "userId: "+storeHandle.getUserId());
        api.signInOptionResponse(storeHandle.getSignGetInResult(), clientDataJsonReviseString, authenticatorDataBase64, signatureBase64,storeHandle.getUserId(), new AuthApi.SignRequestInterface() {
            @Override
            public void SignRequestSuccess(JSONObject jsonObject) {
                Log.e("TAG", "SignRequestSuccess: "+jsonObject.toString());
                runOnUiThread(()->{
                    Toast.makeText(getApplicationContext(),"登入成功",Toast.LENGTH_SHORT).show();
                });
                Intent intent = new Intent(LoginActivity.this,CredentialsActivity.class);
                startActivity(intent);
                finish();
            }

            @Override
            public void SignRequestFail(String msg) {
                Log.e("SignRequestFail", "SignRequestFail: "+msg );
            }
        });

    }
    //-------------------------------------------------------------------//
}