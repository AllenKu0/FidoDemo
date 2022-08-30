package com.example.fido_j.api;

import android.content.ComponentName;
import android.content.Context;
import android.os.Build;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import com.example.fido_j.BuildConfig;
import com.example.fido_j.PreferenceData;
import com.google.android.gms.fido.common.Transport;
import com.google.android.gms.fido.fido2.api.common.Attachment;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAttestationResponse;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorSelectionCriteria;
import com.google.android.gms.fido.fido2.api.common.EC2Algorithm;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredential;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialCreationOptions;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialDescriptor;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialParameters;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRequestOptions;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRpEntity;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialType;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialUserEntity;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.Cookie;
import okhttp3.CookieJar;
import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class AuthApi {
    private String username;
    private String challenge;


    private static final HashMap<String,List<Cookie>> cookieStore = new HashMap<>();
    private PublicKeyCredentialRpEntity optionRpEntity;
    private PublicKeyCredentialUserEntity optionUserEntity;
    public PublicKeyCredentialDescriptor descriptorEntity;
    private List<PublicKeyCredentialParameters> parametersList;
    private AuthenticatorSelectionCriteria.Builder authenticatorEntity;
    private PublicKeyCredentialCreationOptions options;
    private PublicKeyCredentialRequestOptions requestOptions;
    OkHttpClient client = new OkHttpClient().newBuilder()
            .cookieJar(new CookieJar() {
                @Override
                public void saveFromResponse(@NonNull HttpUrl httpUrl, @NonNull List<Cookie> list) {
                    cookieStore.put(httpUrl.host(),list);
                    Log.d("HttpUrl:",""+httpUrl);
                }

                @NonNull
                @Override
                public List<Cookie> loadForRequest(@NonNull HttpUrl httpUrl) {
                    List<Cookie> cookies = cookieStore.get(httpUrl.host());
                    if(cookies!=null){
                        Log.d("Cookie",""+cookies.get(0));
                    }
                    return cookies!=null ? cookies:new ArrayList<Cookie>();
                }
            })
            .build();

    public static final String BASE_URL = "https://zero-trust-test.nutc-imac.com";
    //帳號api
    public void username(String username, AccountInterface accountInterface){
        this.username=username;
        MediaType JSON
                = MediaType.parse("application/json; charset=utf-8");
        JSONObject json = new JSONObject();
        try {
            json.put("username",username);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        RequestBody body = RequestBody.create(String.valueOf(json), JSON); // new
        Request request = new Request.Builder()
                .url(BASE_URL+"/username")
                .post(body)
                .build();
        Call call = client.newCall(request);
        call.enqueue(new Callback() {
            @Override
            public void onFailure(@NonNull Call call, @NonNull IOException e) {
                 accountInterface.AccountFail(e.toString());
            }

            @RequiresApi(api = Build.VERSION_CODES.O)
            @Override
            public void onResponse(@NonNull Call call, @NonNull Response response) throws IOException {
                // 連線成功
                String result = response.body().string();
                Log.d("result username:",""+result);
                accountInterface.AccountSuccess(result);
            }
        });

    }
    //拿註冊所需api(RP，USER等資訊)
    public void registerFidoOptions(OptionsRequestInterface optionsRequestInterface){
        Request request = new Request.Builder()
                .url(BASE_URL+"/generate-registration-options")
                .header("X-Requested-With","XMLHttpRequest")
                .get()
                .build();
        Call call = client.newCall(request);
        call.enqueue(new Callback() {
            @Override
            public void onFailure(@NonNull Call call, @NonNull IOException e) {
                optionsRequestInterface.OptionsFail(e.getMessage());
            }

            @Override
            public void onResponse(@NonNull Call call, @NonNull Response response) throws IOException {
                String result = response.body().string();
                try {
                    JSONObject json = new JSONObject(result);
                    if(json.getString("challenge")!=null){
                        try{
                            challenge= String.valueOf(json.get("challenge"));
                        }
                        catch(Exception e){
                            Log.d("ChallengeError",""+e.getMessage());
                        }
                    }
                    Log.d("Challenge",""+json.get("challenge"));
                    Log.d("JsonRequest",""+json.toString());
                    JSONObject rp = json.getJSONObject("rp");
                    JSONObject user = json.getJSONObject("user");
                    JSONArray pubKeyParams = json.getJSONArray("pubKeyCredParams");
                    JSONObject authenticatorSelection = json.getJSONObject("authenticatorSelection");
                    Log.e("sajhdkj", "onResponse:id "+String.valueOf(rp.get("id"))+" ,name: "+ String.valueOf(rp.get("name") ));
                    if(optionRpEntity==null) {
                        optionRpEntity = new PublicKeyCredentialRpEntity(String.valueOf(rp.get("id")), String.valueOf(rp.get("name")), null);
                    }
                    if (optionUserEntity==null) {
                        optionUserEntity= new PublicKeyCredentialUserEntity(
                                String.valueOf(user.get("id")).getBytes(),
                                String.valueOf(user.get("name")),
                                null,
                                String.valueOf(user.get("displayName"))
                        );
                    }
                    parametersList = Collections.singletonList(new PublicKeyCredentialParameters(
                            PublicKeyCredentialType.PUBLIC_KEY.toString(),
                            EC2Algorithm.ES256.getAlgoValue()
                    ));
                    authenticatorEntity = new AuthenticatorSelectionCriteria.Builder();
                    authenticatorEntity.setAttachment(Attachment.PLATFORM);
//                    authenticatorEntity.setAttachment(Attachment.fromString(authenticatorSelection.getString("authenticatorAttachment")));
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {

                        options = new PublicKeyCredentialCreationOptions.Builder()
                                .setUser(optionUserEntity)
                                .setChallenge(java.util.Base64.getUrlDecoder().decode(challenge))
                                .setParameters(parametersList)
                                .setTimeoutSeconds(Double.valueOf(1800000))
                                .setAuthenticatorSelection(authenticatorEntity.build())
                                .setRp(optionRpEntity)
                                .build();
                    }
                    optionsRequestInterface.OptionsSuccess(options,user);
                } catch (JSONException e) {
                    Log.d("ChallengeErr",""+e.getMessage());
                }
                Log.d("RegisterResult:",""+result);
            }
        });
    }

    //註冊最後一步
    public void registerOptionResponse(String keyHandle,String clientDataJSON,String attestationObject,PublicKeyCredential credential,ResponseInterface responseInterface){
        MediaType JSON
                = MediaType.parse("application/json; charset=utf-8");
        JSONObject json = new JSONObject();
        JSONObject response = new JSONObject();
        JSONObject clientExtensionResults = new JSONObject();
        ArrayList<String> transportsList = new ArrayList<>();
        transportsList.add("internal");
        JSONArray transports = new JSONArray(transportsList);
        try {
            json.put("id",credential.getId());
            json.put("rawId",credential.getId());
            response.put("attestationObject",attestationObject);
            response.put("clientDataJSON",clientDataJSON);
            json.putOpt("response",response);
            json.put("type",PublicKeyCredentialType.PUBLIC_KEY.toString());
            json.put("clientExtensionResults",clientExtensionResults);
            json.put("transports",transports);
            Log.d("registerOptionResponse",""+json.toString());
        } catch (JSONException e) {
            e.printStackTrace();
        }
        RequestBody body = RequestBody.create(String.valueOf(json), JSON); // new
        Request request = new Request.Builder()
                .url(BASE_URL+"/verify-registration-response")
                .header("X-Requested-With","XMLHttpRequest")
                .header("User-Agent", BuildConfig.APPLICATION_ID+"/"+BuildConfig.VERSION_NAME +
                        "(Android "+Build.VERSION.RELEASE+"; "+Build.MODEL+"; "+Build.BRAND+")")
                .post(body)
                .build();
        Call call = client.newCall(request);
        call.enqueue(new Callback() {
            @Override
            public void onFailure(@NonNull Call call, @NonNull IOException e) {
                Log.d("RegisterResponseErr",""+e.getMessage());
                responseInterface.ResponseFail(e.getMessage());
            }

            @Override
            public void onResponse(@NonNull Call call, @NonNull Response response) throws IOException {
                String result = response.body().string();
                Log.d("RegisterResponseSuccess",""+result);
                try {
                    JSONObject json = new JSONObject(result);
                    if(json.getString("username")!=null){
                        responseInterface.ResponseSuccess(json);
                    }
                } catch (Exception e) {
                    responseInterface.ResponseFail(e.getMessage());
                }
            }
        });
    }

    //登入要求api
    public void sigInOptionRequest(Context context,SignOptionGet signOptionGet){
        Request request = new Request.Builder()
                .url(BASE_URL+"/generate-authentication-options")
                .header("X-Requested-With","XMLHttpRequest")
                .get()
                .build();
        Call call = client.newCall(request);
        call.enqueue(new Callback() {
            @Override
            public void onFailure(@NonNull Call call, @NonNull IOException e) {
                signOptionGet.SignOptionGetFail(e.getMessage());
            }

            @Override
            public void onResponse(@NonNull Call call, @NonNull Response response) throws IOException {
                String result = response.body().string();
                PreferenceData storeHandle = new PreferenceData(context);
                Log.e("result","sigInOptionRequest onResponse:"+result);
                try {
                    ArrayList<Transport> transports= new ArrayList<>();
                    transports.add(Transport.INTERNAL);
                    JSONObject json = new JSONObject(result);
                    Log.e("TAG", "onResponse: "+json.getString("challenge"));
                    if(descriptorEntity==null){
                        JSONObject allowCredentials = json.getJSONArray("allowCredentials").getJSONObject(0);
                        Log.d("tagggggg",""+storeHandle.loadKeyHandle());
                        descriptorEntity=new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY.toString(),
                                storeHandle.loadKeyHandle(),
                                transports
                        );
                    }
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        requestOptions = new PublicKeyCredentialRequestOptions.Builder()
                                .setRpId(String.valueOf(json.get("rpId")))
                                .setChallenge(Base64.getUrlDecoder().decode(json.getString("challenge")))
                                //身分驗證器
                                .setAllowList(Collections.singletonList(descriptorEntity))
                                .setTimeoutSeconds(Double.valueOf(1800000))
                                .build();
                    }
                    signOptionGet.SignOptionGetSuccess(requestOptions,result);
                } catch (JSONException e) {
                    Log.d("ChallengeErr",""+e.getMessage());
                }
                Log.d("sigInOptionRequest:","result: "+result);
            }
        });
    }
    //登入 post驗證 api
    public void signInOptionResponse(String result, String clientDataString,String authenticatorDataBase64,String signatureBase64,String keyHandleBase64,SignRequestInterface signRequestInterface) throws JSONException {
        Log.e("TAG", "signInOptionResponse: result"+result );
        Log.e("TAG", "clientDataString: "+clientDataString );
        //回傳Body
        JSONObject json = new JSONObject();
        //result to JSON
        JSONObject resultJson = new JSONObject(result);
        // id
        Log.e("TAG", "signInOptionResponse: "+resultJson.getJSONArray("allowCredentials").get(0).toString());
        JSONObject allowCredentialsJSON = new JSONObject(resultJson.getJSONArray("allowCredentials").get(0).toString());

        MediaType JSON
                = MediaType.parse("application/json; charset=utf-8");
        JSONObject clientExtensionResults = new JSONObject();
        JSONObject responseJson = new JSONObject();
        Log.e("TAG", "signInOptionResponse:e04 "+authenticatorDataBase64 );
        try {
            json.put("id",allowCredentialsJSON.get("id"));
            json.put("rawId",allowCredentialsJSON.get("id"));
            responseJson.put("authenticatorData",authenticatorDataBase64);
            responseJson.put("clientDataJSON",clientDataString);
            responseJson.put("signature",signatureBase64);
            responseJson.put("userHandle",keyHandleBase64);
            json.putOpt("response",responseJson);
            json.put("type",PublicKeyCredentialType.PUBLIC_KEY.toString());
            json.put("clientExtensionResults",clientExtensionResults);
            Log.d("TAG","signInOptionResponseBody :"+json.toString());
        } catch (JSONException e) {
            e.printStackTrace();
        }
        //此api不用json值
        RequestBody body = RequestBody.create(String.valueOf(json), JSON); // new
        Request request = new Request.Builder()
                .url(BASE_URL+"/verify-authentication-response")
                .header("User-Agent", BuildConfig.APPLICATION_ID+"/"+BuildConfig.VERSION_NAME +
                        "(Android "+Build.VERSION.RELEASE+"; "+Build.MODEL+"; "+Build.BRAND+")")
                .header("Origin","https://zero-trust-test.nutc-imac.com")
                .header("Referer","https://zero-trust-test.nutc-imac.com")
                .header("Accept-Encoding","gzip, deflate, br")
                .header("Sec-Fetch-Site","same-origin")
                .header("Sec-Fetch-Mode","cors")
                .header("Sec-Fetch-Dest","empty")
                .post(body)
                .build();
        Call call = client.newCall(request);
        call.enqueue(new Callback() {
            @Override
            public void onFailure(@NonNull Call call, @NonNull IOException e) {
                Log.e("TAG", "onFailure: "+e.getMessage() );
                signRequestInterface.SignRequestFail(e.getMessage());
            }

            @Override
            public void onResponse(@NonNull Call call, @NonNull Response response) throws IOException {
                Log.e("TAG", "onResponse: "+response.toString());
                signRequestInterface.SignRequestSuccess(json);

            }
        });
    }

    public interface AccountInterface{
        void AccountSuccess(String result);
        void AccountFail(String msg);
    }
    public interface OptionsRequestInterface{
        void OptionsSuccess(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions,JSONObject user) throws JSONException;
        void OptionsFail(String msg);
    }
    public interface ResponseInterface{
        void ResponseSuccess(JSONObject json);
        void ResponseFail(String msg);
    }
    public interface SignRequestInterface{
        void SignRequestSuccess(JSONObject json);
        void SignRequestFail(String msg);
    }

    public interface SignOptionGet{
        void SignOptionGetSuccess(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,String result);
        void SignOptionGetFail(String msg);
    }
}

