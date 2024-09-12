import React from "react";

/**
 * Decodes a base64url-encoded string (which differs from base64 at digits 62 and 63)
 */
export function decodeBase64url(str: string) {
	return atob(str.replace(/-/g, "+").replace(/_/g, "/"))
}

/**
 * Turns a string (its characters should have a Unicode value below 256) into a Uint8Array
 * for use with APIs like Crypto that require an ArrayBuffer
 */
export function stringToBuffer(str: string) {
	return new Uint8Array([...str].map(c => c.charCodeAt(0)))
}

// SamlVerify is a component that is used to verify the SAML response that is being redirected by the reverse proxy
export const SAMLVerify = ({ search: searchParams }: { search: string }) => {
	/**
	 * The reason why we are not using useSearchParams here is because it is conveniently decoding URL encoded characters,
	 * SAMLResponse is a base64 encoded string thus it will replace the '+' character with a space 
	 */
	const relayState = searchParams.match(/relayState=([^&]*)/)?.[1];
	const SAMLResponse = searchParams.match(/SAMLResponse=([^&]*)/)?.[1];
  
	window.opener.postMessage({ SAMLResponse, relayState }, window.location.origin);
  
	return <div>this page can be closed now</div>;
  }
