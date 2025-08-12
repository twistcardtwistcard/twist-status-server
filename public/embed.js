(function () {
  var FORM_URL = "https://twist-status-server.onrender.com/twistpay-form";
  var ALLOWED_PARENTS = [
    "https://twistcard.ca",
    "https://www.twistcard.ca",
    "https://draecollection.com",
    "https://www.draecollection.com",
    "https://app.twistcard.ca"
    // add more: "https://staging.example.com"
  ];

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

  var currentScript = document.currentScript || (function () {
    var scripts = document.getElementsByTagName("script");
    return scripts[scripts.length - 1];
  })();

  var amountParam = currentScript.getAttribute("data-amount-param") || "amount";
  var ordernoParam = currentScript.getAttribute("data-orderno-param") || "orderno";
  var emailParam  = currentScript.getAttribute("data-email-param")  || "email";

  var sp = new URLSearchParams(window.location.search);
  var amount  = sp.get(amountParam)  || "";
  var orderno = sp.get(ordernoParam) || "";
  var email   = sp.get(emailParam)   || "";

  var src = FORM_URL + "?" + new URLSearchParams({ amount, orderno, email }).toString();

  var container = document.createElement("div");
  container.style.maxWidth = "560px";
  container.style.margin = "0 auto";

  var iframe = document.createElement("iframe");
  iframe.src = src;
  iframe.width = "100%";
  iframe.height = "980";
  iframe.style.border = "0";
  iframe.allow = "clipboard-read; clipboard-write";
  iframe.setAttribute("title", "Twist Card Payment");

  container.appendChild(iframe);
  currentScript.parentNode.insertBefore(container, currentScript.nextSibling);
})();
