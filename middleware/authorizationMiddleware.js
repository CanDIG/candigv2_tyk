// WARNING please remember to change these:
var vaultUrl = "http://0.0.0.0:8200";
var vaultRole = "test-role";

var testMiddleware = new TykJS.TykMiddleware.NewMiddleware({});

testMiddleware.NewProcessRequest(function(request, session, spec) {
    log("Running the authz middleware")

    if (request.Headers["X-CanDIG-Authz"] === undefined) {
        var token = request.Headers["Authorization"][0].split(" ")[1];
        var tokenPayload = token.split(".")[1];
        var decodedPayload = JSON.parse(b64dec(tokenPayload));

        // Hm use sub (UUID) or preferred_username?
        var userId = decodedPayload.sub;
        
        var data = {
            "jwt": token,
            "role": vaultRole
        };
        var requestParams = {
            "Method": "POST",
            "Domain": vaultUrl,
            "Resource": "/v1/auth/jwt/login",
            "Body": JSON.stringify(data)
        };

        var resp = TykMakeHttpRequest(JSON.stringify(requestParams));
        var respJson = JSON.parse(resp);

        if (respJson.Code == 200) {
            // Yup we need two JSON.parse
            var vaultJson = JSON.parse(respJson.Body);
            var vaultToken = vaultJson.auth.client_token;
            
            var headers = {
                "X-Vault-Token": vaultToken
            };
            // We have validated the JWT and gotten an access token for Vault
            // we can now fetch the entitlements at /v1/secret/data/$userId
            // TODO: will have to decide on the path for these, inside vault
            // this path being user-created, we can do whatever
            var requestParams = {
                "Headers": headers,
                "Method": "GET",
                "Domain": vaultUrl,
                "Resource": "/v1/identity/oidc/token/" + vaultRole,
            };

            var resp = TykMakeHttpRequest(JSON.stringify(requestParams));
            var respJson = JSON.parse(resp);
            
            if (respJson.Code == 200) {
                var vaultData = JSON.parse(respJson.Body);

                request.SetHeaders['X-CanDIG-Authz'] = 'Bearer ' + vaultData.data.token;
            }
        }
    }
    
    return testMiddleware.ReturnData(request, session.meta_data);
});
    
log("New test authz middleware initialised");
