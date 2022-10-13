var client = new XMLHttpRequest();
client.open("GET", "token", true);
client.send();

client.onreadystatechange = function() {
  if(this.readyState == this.HEADERS_RECEIVED) {
    var token = client.getResponseHeader("Authorization");
    token = window.localStorage.setItem("token",token);

  }
}

document.addEventListener("DOMContentLoaded", () => {
  const inputField = document.getElementById("input");
  inputField.addEventListener("keydown", (e) => {
    if (e.code === "Enter") {
      let input = inputField.value;
      inputField.value = "";
      output(input);
    }
  });
});

function output(input) {
  let product;

  let text = input.toLowerCase().replace(/[^\w\s]/gi, "").replace(/[\d]/gi, "").trim();
  text = text
    .replace(/ a /g, " ")
    .replace(/i feel /g, "")
    .replace(/whats/g, "what is")
    .replace(/please /g, "")
    .replace(/ please/g, "")
    .replace(/r u/g, "are you")
    .replace(/allroles/,"");
    var xhttp = new XMLHttpRequest();

    xhttp.onreadystatechange = function() {
  if (this.readyState == 4 && this.status == 200) {
    addChat(text, this.responseText);
    }
  };
  xhttp.open("POST", "./chat", true);
  xhttp.setRequestHeader('content-type', 'application/x-www-form-urlencoded;charset=UTF-8');
  token = window.localStorage.getItem("token");
  xhttp.setRequestHeader('Authorization', token);

  xhttp.send(`text=${text}`);
  // Update DOM

}


function addChat(input, product) {
  const messagesContainer = document.getElementById("messages");

  let userDiv = document.createElement("div");
  userDiv.id = "user";
  userDiv.className = "user response";
  userDiv.innerHTML = `<img src="static/style/images/user.png" class="avatar"><span>${input}</span>`;
  messagesContainer.appendChild(userDiv);

  let botDiv = document.createElement("div");
  let botImg = document.createElement("img");
  let botText = document.createElement("span");
  botDiv.id = "bot";
  botImg.src = "static/style/images/robot.png";
  botImg.className = "avatar";
  botDiv.className = "bot response";
  botText.innerText = "Typing...";
  botDiv.appendChild(botText);
  botDiv.appendChild(botImg);
  messagesContainer.appendChild(botDiv);
  // Keep messages at most recent
  messagesContainer.scrollTop = messagesContainer.scrollHeight - messagesContainer.clientHeight;

  setTimeout(() => {
    botText.innerText = `${product}`;
  }, 2000
  )

}