package play.modules.facebook;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.restfb.DefaultFacebookClient;
import com.restfb.FacebookClient;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import play.exceptions.UnexpectedException;
import play.libs.WS;
import play.libs.WS.HttpResponse;
import play.Logger;
import play.mvc.Http.Cookie;
import play.mvc.Http.Request;
import play.Play;

/**
 * FbGraph provides simple access to the Facebook Graph API.
 *
 * @author Eric Jacob
 */
public class FbGraph {

	public final static String FB_GRAPH_URL = "https://graph.facebook.com/";
	public final static String FB_GRAPH_TOKEN = "FbGraph.token";
	private static Map<String, String> domainAppIds;
	private static Map<String, String> domainAppSecrets;

	public static void init() {
		domainAppIds = new HashMap<String, String>();
		domainAppSecrets = new HashMap<String, String>();
	}

	/**
	 * Returns the Id associated to this application.
	 *
	 * @return the application Id
	 */
	public static String getAppId(String domain) {
		// check if the domain exists in the Map
		// if not read it from the config and add it to the Map
		if (domainAppIds.containsKey(domain)) {
			return domainAppIds.get(domain);
		}
		String newAppId = Play.configuration.getProperty("fbg." + domain + ".appId");
		domainAppIds.put(domain, newAppId);
		return newAppId;
	}

	/**
	 * Returns the Secret associated to this application.
	 *
	 * @return the application Secret
	 */
	public static String getAppSecret(String domain) {
		// check if the appSecret key exists in the Map
		// otherwise read it from the config file and add it to
		// the map
		if (domainAppSecrets.containsKey(domain)) {
			return domainAppSecrets.get(domain);
		}
		String newAppSecret = Play.configuration.getProperty("fbg." + domain + ".appSecret");
		domainAppSecrets.put(domain, newAppSecret);
		return newAppSecret;
	}

	private static Map<String, String> parseStr(String str) {
		String[] pairs = str.split("&");
		Map<String, String> map = new HashMap<String, String>();
		for (String pair : pairs) {
			String[] kv = pair.split("=");
			map.put(kv[0], kv[1]);
		}
		return map;
	}

	/**
	 * Constructs and returns the name of the cookie that potentially houses the
	 * signed request for the app user. The cookie is not set by the FbGraph
	 * class, but it may be set by the JavaScript SDK.
	 *
	 * @return the name of the cookie that would house the signed request
	 */
	protected static String getSignedRequestCookieName(String domain) {
		return "fbsr_" + getAppId(domain);
	}

	/**
	 * Retrieve the signed request, either from a request parameter or, if not
	 * present, from a cookie.
	 *
	 * @return the signed request if available or null otherwise
	 */
	public static SignedRequest getSignedRequest(String domain) {
		SignedRequest signedReq = null;
		String signedReqParam = Request.current().params.get("signed_request");
		if (signedReqParam != null) {
			signedReq = new SignedRequest(signedReqParam);
		}
		else {
			Cookie fbCookie = Request.current().cookies.get(getSignedRequestCookieName(domain));
			if (fbCookie != null) {
				signedReq = new SignedRequest(fbCookie.value);
			}
		}
		return signedReq;
	}

	/**
	 * Returns the data stored in the signed request.
	 *
	 * @return the data stored in the signed request or null otherwise
	 */
	public static JsonObject getFacebookData(String domain) {
		SignedRequest signedReq = getSignedRequest(domain);
		if (signedReq != null && signedReq.verify(getAppSecret(domain))) {
			return signedReq.getData();
		}
		else {
			Logger.error("Signed request not present or invalid");
			return null;
		}
	}

    /**
     * Returns the user access token associated with this application.
     *
     * @return  the user access token
               or null otherwise
     */
    public static String getAccessToken(String domain) {
        String accessToken = null;
        Request req = Request.current();
        if (req.args.containsKey(FB_GRAPH_TOKEN)) {
            accessToken = (String) Request.current().args.get(FB_GRAPH_TOKEN);
        } else {
            JsonObject fbData = getFacebookData(domain);
 	    if(fbData!=null && fbData.has("oauth_token")){
            	accessToken=fbData.get("oauth_token").getAsString();
            }
            else if (fbData != null && fbData.has("code")) {
                HttpResponse res = WS.url(FB_GRAPH_URL + "oauth/access_token?"
                        + "client_id=" + getAppId(domain)
                        + "&client_secret="
                        + getAppSecret(domain) +"&redirect_uri="
                        + "&code=" + fbData.get("code").getAsString()).get();

                if (res.getJson() != null && res.getJson().getAsJsonObject().get("access_token")!= null) {
                    accessToken = res.getJson().getAsJsonObject().get("access_token").getAsString();
                    req.args.put(FB_GRAPH_TOKEN, accessToken);
                }
            }
        }
        Logger.debug("Access token: %s", accessToken);
        return accessToken;
    }

	/**
	 * Destroy the current session.
	 */
	public static void destroySession(String domain) {
		Request req = Request.current();
		if (req.args.containsKey(FB_GRAPH_TOKEN)) {
			req.args.remove(FB_GRAPH_TOKEN);
		}
		if (req.cookies.containsKey(getSignedRequestCookieName(domain))) {
			req.cookies.remove(getSignedRequestCookieName(domain));
		}
		Logger.info("Session destroyed");
	}

	/**
	 * Executes a GET or POST request to the Graph API.
	 *
	 * @param path
	 *            - the URL path
	 * @param method
	 *            - the HTTP method (optional, default "GET")
	 * @param params
	 *            - the parameters for the query (optional)
	 * @return the HTTP response
	 */
	private static HttpResponse makeRequest(String path, String method, Map<String, String> params) {
		StringBuilder url = new StringBuilder();
		url.append(FB_GRAPH_URL);
		if (path.startsWith("/")) {
			path = path.substring(1);
		}
		url.append(path);
		StringBuilder queryStr = new StringBuilder();
		for (Map.Entry<String, String> param : params.entrySet()) {
			if (queryStr.length() > 0) {
				queryStr.append("&");
			}
			queryStr.append(WS.encode(param.getKey()));
			queryStr.append("=");
			queryStr.append(WS.encode(param.getValue()));
		}
		if (method != null && method.toUpperCase().equals("POST")) {
			Logger.info("Making a POST request to URL %s with body set to %s", url.toString(), queryStr.toString());
			return WS.url(url.toString()).body(queryStr.toString()).mimeType("multipart/form-data").post();
		}
		else {
			url.append("?");
			url.append(queryStr.toString());
			Logger.info("Making a GET request to URL %s", url.toString());
			return WS.url(url.toString()).get();
		}
	}

	/**
	 * Performs an authorized request to the Graph API.
	 *
	 * @param path
	 *            - the URL path
	 * @param method
	 *            - the HTTP method (optional, default "GET")
	 * @param params
	 *            - the parameters for the query (optional)
	 * @return the HTTP response
	 */
	private static HttpResponse oauthRequest(String domain, String path, String method, Map<String, String> params)
			throws FbGraphException {
		if (params == null) {
			params = new HashMap<String, String>();
		}
		String accessToken = null;
		if (params.containsKey("access_token")) {
			accessToken = params.get("access_token");
		}
		else {
			accessToken = getAccessToken(domain);
			params.put("access_token", accessToken);
		}
		if (accessToken == null) {
			throw new FbGraphException("No valid access token");
		}
		return makeRequest(path, method, params);
	}

	/**
	 * Executes an API call to the Graph API.
	 *
	 * @param path
	 *            - the URL path, e.g. "me/friends"
	 * @param method
	 *            - the HTTP method (optional, default "GET")
	 * @param params
	 *            - the parameters for the query (optional)
	 * @return the response object
	 * @throws FbGraphException
	 */
	public static JsonElement api(String domain, String path, String method, Map<String, String> params)
			throws FbGraphException {
		HttpResponse res = oauthRequest(domain, path, method, params);
		if (res == null) {
			throw new UnexpectedException("Module FbGraph got an unexpected response from facebook");
		}
		if (res.getStatus() != 200) {
			throw new FbGraphException("HttpResponse", Integer.toString(res.getStatus()), res.getString());
		}
		JsonElement json = res.getJson();
		if (json.isJsonObject()) {
			JsonObject jsonObject = (JsonObject) json;
			if (jsonObject.get("error") != null) {
				throw new FbGraphException(jsonObject);
			}
		}
		return json;
	}

	/**
	 * Executes an API call to the Graph API.
	 *
	 * @param path
	 *            - the URL path, e.g. "me/friends"
	 * @param method
	 *            - the HTTP method (optional, default "GET")
	 * @return the response object
	 * @throws FbGraphException
	 */
	public static JsonElement api(String domain, String path, String method) throws FbGraphException {
		return api(domain, path, method, new HashMap<String, String>());
	}

	/**
	 * Executes an API call to the Graph API.
	 *
	 * @param path
	 *            - the URL path, e.g. "me/friends"
	 * @param params
	 *            - the parameters for the query (optional)
	 * @return the response object
	 * @throws FbGraphException
	 */
	public static JsonElement api(String domain, String path, Map<String, String> params) throws FbGraphException {
		return api(domain, path, "GET", params);
	}

	/**
	 * Executes an API call to the Graph API.
	 *
	 * @param path
	 *            - the URL path, e.g. "me/friends"
	 * @return the response object
	 * @throws FbGraphException
	 */
	public static JsonElement api(String domain, String path) throws FbGraphException {
		return api(domain, path, "GET", new HashMap<String, String>());
	}

	/**
	 * Fetches a single object to the Graph API.
	 *
	 * @param objId
	 *            - the ID of the object, e.g. "me"
	 * @param params
	 *            - the parameters for the query (optional)
	 * @return the response object
	 * @throws FbGraphException
	 */
	public static JsonObject getObject(String domain, String objId, Map<String, String> params) throws FbGraphException {
		return api(domain, objId, params).getAsJsonObject();
	}

	/**
	 * Fetches a single Graph API object.
	 *
	 * @param objId
	 *            - the ID of the object, e.g. "me"
	 * @return the response object
	 * @throws FbGraphException
	 */
	public static JsonObject getObject(String domain, String objId) throws FbGraphException {
		return getObject(domain, objId, new HashMap<String, String>());
	}

	/**
	 * Fetches a single object to the Graph API.
	 *
	 * @param objId
	 *            - the ID of the object, e.g. "me"
	 * @param clazz
	 *            - the object type
	 * @param params
	 *            - the parameters for the query (optional)
	 * @return the response object
	 * @throws FbGraphException
	 */
	public static <T> T getObject(String domain, String objId, Class<T> clazz, Map<String, String> params)
			throws FbGraphException {
		return JsonUtil.toJavaObject(getObject(domain, objId, params), clazz);
	}

	/**
	 * Fetches a single Graph API object.
	 *
	 * @param objId
	 *            - the ID of the object, e.g. "me"
	 * @param clazz
	 *            - the object type
	 * @return the response object
	 * @throws FbGraphException
	 */
	public static <T> T getObject(String domain, String objId, Class<T> clazz) throws FbGraphException {
		return getObject(domain, objId, clazz, new HashMap<String, String>());
	}

	/**
	 * Fetches multiple Graph API objects.
	 *
	 * @param ids
	 *            - the IDs of the objects
	 * @return the response objects
	 * @throws FbGraphException
	 */
	public static JsonObject getObjects(String domain, Map<String, String> ids) throws FbGraphException {
		return getObject(domain, "", ids);
	}

	/**
	 * Fetches a Graph API connection.
	 *
	 * @param conId
	 *            - the ID/CONNECTION_TYPE string, e.g. "me/friends"
	 * @param params
	 *            - the parameters for the query (optional)
	 * @return the response object
	 * @throws FbGraphException
	 */
	public static JsonArray getConnection(String domain, String conId, Map<String, String> params)
			throws FbGraphException {
		return api(domain, conId, params).getAsJsonObject().get("data").getAsJsonArray();
	}

	/**
	 * Fetches a Graph API connection.
	 *
	 * @param conId
	 *            - the ID/CONNECTION_TYPE string, e.g. "me/friends"
	 * @return the response object
	 * @throws FbGraphException
	 */
	public static JsonArray getConnection(String domain, String conId) throws FbGraphException {
		return getConnection(domain, conId, new HashMap<String, String>());
	}

	/**
	 * Fetches a Graph API connection.
	 *
	 * @param conId
	 *            - the ID/CONNECTION_TYPE string, e.g. "me/friends"
	 * @param clazz
	 *            - the object type
	 * @param params
	 *            - the parameters for the query (optional)
	 * @return the response object
	 * @throws FbGraphException
	 */
	public static <T> List<T> getConnection(String domain, String conId, Class<T> clazz, Map<String, String> params)
			throws FbGraphException {
		return JsonUtil.toJavaObject(getConnection(domain, conId, params), clazz);
	}

	/**
	 * Fetches a Graph API connection.
	 *
	 * @param conId
	 *            - the ID/CONNECTION_TYPE string, e.g. "me/friends"
	 * @param clazz
	 *            - the object type
	 * @return the response object
	 * @throws FbGraphException
	 */
	public static <T> List<T> getConnection(String domain, String conId, Class<T> clazz) throws FbGraphException {
		return getConnection(domain, conId, clazz, new HashMap<String, String>());
	}

	/**
	 * Returns a picture URL.
	 *
	 * @param picId
	 *            - the ID of the picture
	 * @return the URL of the picture
	 * @throws FbGraphException
	 */
	public static String getPicture(String domain, String picId) throws FbGraphException {
		SignedRequest signedReq = getSignedRequest(domain);
		if (signedReq == null || !signedReq.verify(getAppSecret(domain))) {
			throw new FbGraphException("No Facebook session associated with the user");
		}
		return FB_GRAPH_URL + picId + "/picture?access_token=" + WS.encode(getAccessToken(domain));
	}

	/**
	 * Returns a picture URL.
	 *
	 * @param picId
	 *            - the ID of the picture
	 * @param picType
	 *            - the size of the picture
	 * @return the URL of the picture
	 * @throws FbGraphException
	 */
	public static String getPicture(String domain, String picId, String picType) throws FbGraphException {
		return getPicture(domain, picId) + "&type=" + picType;
	}

	/**
	 * Performs a Graph API publish operation.
	 *
	 * @param path
	 *            - the URL path
	 * @param params
	 *            - the parameters of the post
	 * @return the published Facebook graph object
	 * @throws FbGraphException
	 */
	public static JsonElement publish(String path, Map<String, String> params) throws FbGraphException {
		return api(path, "POST", params);
	}

	/**
	 * Performs a Graph API publish operation.
	 *
	 * @param path
	 *            - the URL path
	 * @param params
	 *            - the parameters of the post
	 * @param clazz
	 *            - the object type
	 * @return the published Facebook graph object
	 * @throws FbGraphException
	 */
	public static <T> T publish(String path, Class<T> clazz, Map<String, String> params) throws FbGraphException {
		return JsonUtil.toJavaObject(publish(path, params).toString(), clazz);
	}

	/**
	 * Performs a Graph API delete operation.
	 *
	 * @param objId
	 *            - the ID of the object
	 * @return true if successful, false otherwise
	 * @throws FbGraphException
	 */
	public static Boolean delete(String objId) throws FbGraphException {
		return api(objId, "POST", Parameter.with("method", "delete").parameters()).getAsBoolean();
	}

	/**
	 * Returns a RestFB Facebook client.
	 *
	 * @return the Facebook client
	 */
	public static FacebookClient getFacebookClient(String domain) {
		return getFacebookClient(getAccessToken(domain));
	}

}
