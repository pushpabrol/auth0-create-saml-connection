require("dotenv").config();
var fs = require('fs');
var dom = require('xmldom').DOMParser;
var xmlserializer = require('xmlserializer');
var sleep = require('sleep');
var _ = require("underscore");
fs.writeFile('./process/rejects.xml', '<EntitiesDescriptor>', function(err){
 if (err) throw err;
  console.log('It\'s saved!');
});

fs.writeFile('./process/connection_already_exists.xml', '<EntitiesDescriptor>', function(err){
 if (err) throw err;
  console.log('It\'s saved!');
});

fs.readFile('./inputs/pse-addons_auth0_com-metadata.xml','utf8', function (err, data) {
if (err) {
return console.log(err);
} else 
{
console.log(data);
var doc = new dom().parseFromString(data);

var entitiesDesc = doc.getElementsByTagName("EntitiesDescriptor")[0];
entities = entitiesDesc.getElementsByTagName("EntityDescriptor")
var y = 0;

var entitiesArray = [];
for(var x=0; x < entities.length; x++)
{

    if(y == 100) break;
    if(entities[x].getElementsByTagName("IDPSSODescriptor").length > 0)
    {
        y= y + 1;
        
         entities[x].setAttribute("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#");
         entities[x].setAttribute("xmlns:alg","urn:oasis:names:tc:SAML:metadata:algsupport");
         entities[x].setAttribute("xmlns:idpdisc","urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol");
         entities[x].setAttribute("xmlns:init","urn:oasis:names:tc:SAML:profiles:SSO:request-init");
         entities[x].setAttribute("xmlns:mdrpi","urn:oasis:names:tc:SAML:metadata:rpi" );
         entities[x].setAttribute("xmlns:mdui","urn:oasis:names:tc:SAML:metadata:ui" );
         entities[x].setAttribute("xmlns:shibmd","urn:mace:shibboleth:metadata:1.0" );
         entities[x].setAttribute("xmlns:xsi","http://www.w3.org/2001/XMLSchema-instance");
         if(!entities[x].getElementsByTagName("IDPSSODescriptor")[0]
         .getElementsByTagName("KeyDescriptor")[0].hasAttribute("use"))
        entities[x].getElementsByTagName("IDPSSODescriptor")[0].getElementsByTagName("KeyDescriptor")[0].setAttribute("use","signing");
        
        //SingleSignOnService and protocolBInding
        var binding ="";
        var children = [];
            var ssoservices = entities[x].getElementsByTagName("IDPSSODescriptor")[0].getElementsByTagName("SingleSignOnService");

             for(var e=0; e < ssoservices.length; e++){
             if(ssoservices[e].getAttribute("Binding") === "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" || ssoservices[e].getAttribute("Binding") === "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ) {

                   if(binding == '') binding = ssoservices[e].getAttribute("Binding");
             } 
             if(ssoservices[e].getAttribute("Binding") !== binding ) children.push(ssoservices[e]);

         }
         
             for(var v=0; v < children.length; v++){
                    entities[x].getElementsByTagName("IDPSSODescriptor")[0].removeChild(children[v]);
             }              

         
         var str = xmlserializer.serializeToString(entities[x]).toString();
         str = str.replace(/\n/gm,""); 
         str = str.replace(/\t/gm,"") 
         str = str.replace(/\r/gm,"")
         str = str.replace(/\r\n/gm,"")
         str = str.replace(/\n*\s+\n*</gm,"<")
         //console.log(str);

         var connName = "pse-addons";

         //console.log(y);


         entitiesArray.push({ name : connName, xmlMetadata : str, binding : binding });

    }
}

console.log("Done gathering...");

 var request = require("request"),
        throttledRequest = require('throttled-request')(request);

        throttledRequest.configure({
        requests: 10,
        milliseconds: 2000
        });//This will throttle the requests so no more than 5 are made every second 

       _.each(entitiesArray, function(entity){
        processEntities(entity,throttledRequest);
        
        });

        fs.appendFileSync('./process/rejects.xml', '</EntitiesDescriptor>', 'utf-8');


}
});

function processEntities(entity,throttledRequest)
{

var tools = require('auth0-extension-tools');

tools.managementApi.getAccessToken( process.env.DOMAIN,  process.env.CLIENT_ID, process.env.CLIENT_SECRET)
.then(function(token) {



  
    var options = { method: 'POST',
    url: `https://${process.env.DOMAIN}/api/v2/connections`,
    headers: 
    { 
        accept: 'application/json',
        'content-type': 'application/json',
        authorization: `Bearer ${token}` },
    body: 
    { 
        name: entity.name,
        strategy: 'samlp',
        options: {
                metadataXml: entity.xmlMetadata,
                entityId : 'https://www.okta.com/saml2/service-provider/spwkqlsxuuhotcrzdbys',
                protocolBinding :entity.binding,
                checkRecipient: false,
                checkDestination: false,
                checkInResponseTo: false,
                "idpinitiated":{ 
                                "enabled":true,
                                "client_protocol":"oauth2",
                                "client_id":process.env.ENABLED_CLIENT_IDs.replace(/\s/g, '').split(",")[0],
                                "client_authorizequery":`response_type=id_token&scope=openid profile email`
                                }
        },
        enabled_clients: process.env.ENABLED_CLIENT_IDs.replace(/\s/g, '').split(",") },
    json: true };
    
    throttledRequest(options, function (error, response, body) {
    if (error)  
    {
        console.log(error);
        console.log(JSON.stringify(error));
        console.log(body);
        fs.appendFileSync('rejects.xml', entity.xmlMetadata, 'utf-8');
    }
    else
    {
            if(response.statusCode == 201 ) console.log("created");
            else if(response.statusCode >= 400) {

               if(response.statusCode == 409) {
                   console.log(entity.name +  " already exists!");
                   fs.appendFileSync('./process/connection_already_exists.xml', entity.xmlMetadata, 'utf-8');
               }
               else {
                console.log(body);
                console.log(entity.name);
                console.log(entity.xmlMetadata);
                fs.appendFileSync('./process/rejects.xml', entity.xmlMetadata, 'utf-8');
               }
            }
            else {
                console.log(body);
            }

    }

    
    });
});
}