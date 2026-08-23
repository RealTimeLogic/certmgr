(function () {
  "use strict";
  var connectionWarningDismissed = false;
  var failedRequestUrl = window.location.href;
  var connectionWarningKind = "";

  function closeMenu() {
    document.body.classList.remove("menu-open");
    var button = document.querySelector("[data-menu-toggle]");
    if (button) button.setAttribute("aria-expanded", "false");
  }
  function updateNavigation() {
    var current = window.location.pathname.toLowerCase();
    if (current.endsWith("/")) current += "index.html";
    document.querySelectorAll(".nav-link").forEach(function (link) {
      var path = new URL(link.href, window.location.href).pathname.toLowerCase();
      var active = path === current ||
        (current.endsWith("/authority.html") && path.endsWith("/authorities.html")) ||
        (current.endsWith("/certificate.html") && path.endsWith("/certificates.html"));
      link.classList.toggle("is-active", active);
      if (active) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });
  }
  function updatePageState() {
    updateNavigation();
    var heading = document.querySelector("#main h1");
    if (heading) document.title = heading.textContent.trim() + " · Certificate Manager";
  }
  function removeConnectionWarning() {
    var overlay = document.getElementById("connectionWarning");
    if (overlay) overlay.remove();
    connectionWarningKind = "";
  }
  function connectionRestored(kind) {
    if (connectionWarningKind && connectionWarningKind !== kind &&
        !(kind === "http" && connectionWarningKind === "network")) return;
    connectionWarningDismissed = false;
    removeConnectionWarning();
  }
  function requestUrl(event) {
    var detail = event && event.detail;
    var pathInfo = detail && detail.pathInfo;
    var requestConfig = detail && detail.requestConfig;
    var source = (detail && detail.elt) || (event && event.target);
    var candidate = (pathInfo && (pathInfo.finalRequestPath || pathInfo.requestPath)) ||
      (requestConfig && requestConfig.path) ||
      (source && source.getAttribute &&
        (source.getAttribute("hx-get") || source.getAttribute("href")));

    if (!candidate) return failedRequestUrl;
    try {
      var url = new URL(candidate, window.location.href);
      return url.origin === window.location.origin ? url.href : failedRequestUrl;
    } catch (error) {
      return failedRequestUrl;
    }
  }
  function requestLabel(url) {
    try {
      var parsed = new URL(url, window.location.href);
      return parsed.pathname + parsed.search;
    } catch (error) {
      return "";
    }
  }
  function retryFailedRequest() {
    window.location.assign(failedRequestUrl || window.location.href);
  }
  function showConnectionWarning(title, message, event, kind) {
    if (connectionWarningDismissed) return;

    failedRequestUrl = requestUrl(event);
    connectionWarningKind = kind || "http";

    var overlay = document.getElementById("connectionWarning");
    if (!overlay) {
      overlay = document.createElement("div");
      overlay.id = "connectionWarning";
      overlay.className = "connection-overlay";
      overlay.setAttribute("role", "alertdialog");
      overlay.setAttribute("aria-modal", "true");
      overlay.setAttribute("aria-labelledby", "connectionWarningTitle");
      overlay.setAttribute("aria-describedby", "connectionWarningMessage connectionWarningRequest");

      var panel = document.createElement("div");
      panel.className = "connection-panel";

      var heading = document.createElement("h2");
      heading.id = "connectionWarningTitle";
      heading.className = "connection-title";

      var detail = document.createElement("p");
      detail.id = "connectionWarningMessage";
      detail.className = "connection-message";

      var request = document.createElement("p");
      request.id = "connectionWarningRequest";
      request.className = "connection-request";

      var actions = document.createElement("div");
      actions.className = "connection-actions";

      var retry = document.createElement("button");
      retry.type = "button";
      retry.className = "connection-button connection-button-primary";
      retry.textContent = "Retry";
      retry.addEventListener("click", retryFailedRequest);

      var dismiss = document.createElement("button");
      dismiss.type = "button";
      dismiss.className = "connection-button connection-button-secondary";
      dismiss.textContent = "Dismiss";
      dismiss.addEventListener("click", function () {
        connectionWarningDismissed = true;
        removeConnectionWarning();
      });

      actions.append(retry, dismiss);
      panel.append(heading, detail, request, actions);
      overlay.appendChild(panel);
      document.body.appendChild(overlay);
    }

    overlay.querySelector(".connection-title").textContent = title;
    overlay.querySelector(".connection-message").textContent = message;
    var label = requestLabel(failedRequestUrl);
    var requestElement = overlay.querySelector(".connection-request");
    requestElement.textContent = label ? "Requested page: " + label : "";
    requestElement.hidden = !label;
    overlay.querySelector(".connection-button-primary").focus();
  }
  function requestFailure(event, fallback) {
    var xhr = event.detail && event.detail.xhr;
    var status = xhr && xhr.status;
    if (status) return "The server returned HTTP " + status + ". Retry when the service is available.";
    return fallback;
  }
  function requestSucceeded(event) {
    if (event.detail && typeof event.detail.successful === "boolean") return event.detail.successful;
    var xhr = event.detail && event.detail.xhr;
    return Boolean(xhr && xhr.status >= 200 && xhr.status < 400);
  }
  document.addEventListener("click", function (event) {
    var guarded = event.target.closest("[data-confirm]");
    if (guarded && !window.confirm(guarded.getAttribute("data-confirm"))) {
      event.preventDefault();
      return;
    }
    var toggle = event.target.closest("[data-menu-toggle]");
    if (toggle) {
      var open = document.body.classList.toggle("menu-open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
      return;
    }
    if (event.target.closest(".nav-link") && window.matchMedia("(max-width: 760px)").matches) closeMenu();
  });
  document.addEventListener("htmx:afterSwap", function () {
    updatePageState();
    closeMenu();
    window.scrollTo({top: 0, behavior: "instant"});
  });
  document.body.addEventListener("htmx:afterRequest", function (event) {
    if (requestSucceeded(event)) {
      connectionRestored("http");
    } else {
      showConnectionWarning(
        "Page update failed",
        requestFailure(event, "The server could not be reached. Check the connection and try again."),
        event
      );
    }
  });
  document.addEventListener("htmx:beforeRequest", function () {
    connectionWarningDismissed = false;
  }, true);
  document.addEventListener("htmx:sendError", function (event) {
    showConnectionWarning(
      "Server unavailable",
      requestFailure(event, "The server could not be reached. Check the connection and try again."),
      event
    );
  }, true);
  document.addEventListener("htmx:timeout", function (event) {
    showConnectionWarning("Request timed out", "The server did not respond within 10 seconds. Try again.", event);
  }, true);
  document.addEventListener("htmx:responseError", function (event) {
    showConnectionWarning(
      "Page update failed",
      requestFailure(event, "The server rejected the page update. Try again."),
      event
    );
  }, true);
  window.addEventListener("offline", function () {
    showConnectionWarning(
      "Network unavailable",
      "This device is offline. Reconnect to the network and try again.",
      undefined,
      "network"
    );
  });
  window.addEventListener("online", function () {
    var overlay = document.getElementById("connectionWarning");
    if (overlay && connectionWarningKind === "network") {
      overlay.querySelector(".connection-title").textContent = "Network connection restored";
      overlay.querySelector(".connection-message").textContent =
        "Retry the requested page to confirm that the server is available.";
    }
  });
  function scheduleNavigationSync() {
    window.setTimeout(updatePageState, 50);
  }
  document.body.addEventListener("htmx:historyRestore", scheduleNavigationSync);
  window.addEventListener("popstate", scheduleNavigationSync);
  document.addEventListener("DOMContentLoaded", updatePageState);
}());
