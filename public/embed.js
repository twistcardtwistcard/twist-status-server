(function () {
  // URL of the hosted form on your server
  var FORM_URL = "https://twist-status-server.onrender.com/twistpay-form";

  // Allowed parent page origins for embedding (add your domains here)
  var ALLOWED_PARENTS = [
    "https://twistcard.ca",
    "https://www.twistcard.ca",
    "https://draecollection.com",
    "https://www.draecollection.com",
    "https://app.twistcard.ca"
  ];

  // Check that the embedding page is on the allowlist
  try {
    var parentHost = window.location !== window.parent.location
      ? document.referrer || ""
      : window.location.href;
    if (!ALLOWED_PARENTS.some(h => parentHost.startsWith(h))) {
      console.warn("[TwistPay Embed] Refused to embed: origin not on allowlist.", parentHost);
      return;
    }
  } catch (e) {
    console.warn("[TwistPay Embed] Could not verify parent origin:", e);
  }

  // Get the <script> tag that loaded this file
  var currentScript = document.currentScript || (function () {
    var scripts = document.getElementsByTagName("script");
    return scripts[scripts.length - 1];
  })();

  // Get the query parameter names from data-* attributes (optional overrides)
  var amountParam = currentScript.getAttribute("data-amount-param") || "amount";
  var ordernoParam = currentScript.getAttribute("data-orderno-param") || "orderno";
  var emailParam  = currentScript.getAttribute("data-email-param")  || "email";

  // Read query parameters from the embedding page's URL
  var sp = new URLSearchParams(window.location.search);
  var amount  = sp.get(amountParam)  || "";
  var orderno = sp.get(ordernoParam) || "";
  var email   = sp.get(emailParam)   || "";

  // Build iframe URL with those values
  var src = FORM_URL + "?" + new URLSearchParams({ amount, orderno, email }).toString();

  // Create a container for the iframe
  var container = document.createElement("div");
  container.style.maxWidth = "560px";
  container.style.margin = "0 auto";

  // Create the iframe
  var iframe = document.createElement("iframe");
  iframe.src = src;
  iframe.width = "100%";
  iframe.height = "980";
  iframe.style.border = "0";
  iframe.allow = "clipboard-read; clipboard-write";

  // Add the iframe to the page
  container.appendChild(iframe);
  currentScript.parentNode.insertBefore(container, currentScript.nextSibling);
})();
