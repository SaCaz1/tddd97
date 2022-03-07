window.onload = function() {
  localStorage.removeItem('profileViewLoaded');
  loadLocalStorage();

  page.start();
}

window.onunload = () => {
  localStorage.removeItem('profileViewLoaded');
}

page('/', function() {
  localStorage.removeItem('profileViewLoaded');
  loadLocalStorage();

  if (userLoggedIn()) {
    connectWebsocket();
    page.redirect('/home');
  } else {
    page.redirect('/welcome');
  }
});

page('/home', function() {
  if (!userLoggedIn()) {
    loadPage();
  };

  if (localStorage.getItem('profileViewLoaded') === null) {
    let pageContent = document.getElementById("pageContent");
    let content = document.getElementById("profileView").innerHTML;
    pageContent.innerHTML = content;

    localStorage.setItem('profileViewLoaded', JSON.stringify(true));
  }
  homeTabClicked();
});

page('/welcome', function() {
  let pageContent = document.getElementById("pageContent");
  let content = document.getElementById("welcomeView").innerHTML;
  pageContent.innerHTML = content;
});

page('/browse', function() {
  if (!userLoggedIn()) {
    loadPage();
  };

  if (localStorage.getItem('profileViewLoaded') === null) {
    let pageContent = document.getElementById("pageContent");
    let content = document.getElementById("profileView").innerHTML;
    pageContent.innerHTML = content;

    localStorage.setItem('profileViewLoaded', JSON.stringify(true));
  }
  tabClicked('browse');
});

page('/account', function() {
  if (!userLoggedIn()) {
    loadPage();
  };

  if (localStorage.getItem('profileViewLoaded') === null) {
    let pageContent = document.getElementById("pageContent");
    let content = document.getElementById("profileView").innerHTML;
    pageContent.innerHTML = content;

    localStorage.setItem('profileViewLoaded', JSON.stringify(true));
  }
  tabClicked('account');
});


page('*', function(){
  console.log("error url");
});

function loadPage() {
  page.redirect('/');
}

function userLoggedIn() {
  if (localStorage.getItem('token') != null) {
    console.log("Token in local storage");
    return true;
  } else {
    return false;
  }
}

function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);

  if (parts.length !== 2){
    return null;
  }
  let cookie = parts.pop().split(';').shift();

  if (name === 'authorized_user' && cookie.startsWith('\"')) {
    cookie = cookie.replaceAll('\"', '');
  }

  return cookie;
}

async function connectWebsocket() {
  let token = localStorage.getItem("token");
  let email = localStorage.getItem("loggedInUserEmail");
  let hash = await sign_crypto(email + token, token);

  let socket = io("ws://" + window.location.hostname + ":5000/autologout", {
    auth: {
      token : hash,
      public_key: email
    }
  });

  socket.on("autologout", () => {
    showErrors(["Log in to your account from another browser took place. You will be logged out."]);

    localStorage.removeItem('token');
    localStorage.removeItem('loggedInUserEmail');
    loadPage();
  });

  socket.on("connect_error", (error) => {
    showErrors(["Auto Logout feature could not be enabled."]);
  });

  socket.on("disconnect", (reason) => {
    showErrors(["Auto Logout feature might not work."]);
  });
}

function loadLocalStorage() {
  let user = getCookie('authorized_user');
  let token = getCookie('session_token');

  if (user != null) {
    localStorage.setItem('loggedInUserEmail', user);
  }

  if (token != null) {
    localStorage.setItem('token', token);
  }
}

// GENERAL FUCTIONS

function showErrors(errorMessages){
  errorMessageBlock = document.getElementById("errorMessage");
  errorMessageBlock.innerHTML = "";

  errorMessages = [...new Set(errorMessages)]; //eliminates duplicates
  errorMessages.forEach(function(message){
    errorMessageBlock.innerHTML += '<p>' + message + "</p>";
  });

  setTimeout(function(){
    errorMessageBlock.innerHTML = "";
  }, 5000);
}

// WELCOME VIEW FUNCTONS

function validateFormAndShowErrors(form) {
  let password = form.newPassword;
  let repeat = form.repeatPSW;

  if (password.value != repeat.value) {
    showErrors(["Repeating password does not match!"]);
    return false;
  }
  return true;
};

async function submitSignUpForm(form) {
  if (!validateFormAndShowErrors(form)) {
    return;
  }

  signUpDto = {
    "email": form.emailSignup.value,
    "password": form.newPassword.value,
    "first_name": form.firstName.value,
    "family_name": form.familyName.value,
    "gender": form.gender.value,
    "city": form.city.value,
    "country": form.country.value
  };

  let response = await fetch('/sign_up', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json;charset=utf-8'
    },
    body: signUpDto
  });

  if (response.ok) {
    let username = signUpDto.email;
    let password = signUpDto.password;

    signIn(username, password);
  } else if (response.status === 400) {
    showErrors(["Invalid input."]);
  } else if (response.status === 409) {
    showErrors(["User already exists."]);
  } else if (response.status === 500) {
    showErrors(["Something went wrong."]);
  } else {
    showErrors(["Something went wrong."]);
  }
};

function submitSignInForm(form) {
  let username = form.emailLogin.value;
  let password = form.password.value;

  signIn(username, password);
};

async function signIn(username, password){
  let signInDto = {"username" : username, "password" : password};

  let response = await fetch('/sign_in', {
    method : 'POST',
    headers: {
      'Content-Type': 'application/json;charset=utf-8'
    },
    body: JSON.stringify(signInDto)
  });

  if (response.ok) {
    result = await response.json();
    localStorage.setItem("token", result.token);
    localStorage.setItem("loggedInUserEmail", username)

    loadPage();
  } else if (response.status === 400) {
    showErrors(["The username or password are missing."]);
  } else if (response.status ===  404) {
    showErrors(["No such user"]);
  } else if (response.status ===  401) {
    showErrors(["Wrong password."]);
  } else {
    showErrors(["Something went wrong."]);
  }
}

function externalSignIn(provider) {
  window.location.replace("/auth/" + provider);
}

// MAIN PAGE FUNCITONS

async function homeTabClicked() {
  let token = localStorage.getItem("token");
  let public_key = localStorage.getItem("loggedInUserEmail");

  let hash = await sign_crypto(public_key + token + "GET" + '/get_user_data', token);
  let userDataResponse = await fetch('/get_user_data', {
    method: 'GET',
    headers: {
      'Authorization': hash,
      'Public-Key': public_key
    }
  });

  if (!userDataResponse.ok) {
    showErrors(["Something went wrong. Please log in again"]);
    localStorage.removeItem('token');
    loadPage();
  }

  hash = await sign_crypto(public_key + token + 'GET' + '/message/get', token);
  let userMessagesResponse = await fetch('/message/get', {
    method : "GET",
    headers: {
      'Authorization': hash,
      'Public-Key': public_key
    }
  });

  if (!userMessagesResponse.ok) {
    showErrors(["Something went wrong. Please log in again"]);
    localStorage.removeItem('token');
    loadPage();
  }

  let userData = await userDataResponse.json();
  let userMessages = await userMessagesResponse.json();

  tabClicked("home");
  loadUserViewToHomePanel(userData, userMessages);
}

function tabClicked(name){
  setVisiblePanel(name + "Panel");
  setSelectedTab(name + "Tab");
}

function setVisiblePanel(name) {
  document.getElementById("homePanel").style.display = "none";
  document.getElementById("browsePanel").style.display = "none";
  document.getElementById("accountPanel").style.display = "none";

  document.getElementById(name).style.display = "block";
}

function setSelectedTab(name) {
  document.getElementById('homeTab').children[0].style.color = "blue";
  document.getElementById("browseTab").children[0].style.color = "blue";
  document.getElementById("accountTab").children[0].style.color = "blue";

  document.getElementById(name).children[0].style.color = "red";
}

function loadUserViewToHomePanel(userData, userMessages) {
  document.getElementById("homePanel").innerHTML = document.getElementById("userHomeView").innerHTML;

  document.getElementById("firstNameLabel").innerHTML = "Name: " + userData.first_name;
  document.getElementById("familyNameLabel").innerHTML = "Family Name: " + userData.family_name;
  document.getElementById("emailLabel").innerHTML = "Email: " + userData.email;
  document.getElementById("genderLabel").innerHTML = "Gender: " + userData.gender;
  document.getElementById("cityLabel").innerHTML = "City: " + userData.city;
  document.getElementById("countryLabel").innerHTML = "Country: " + userData.country;

  showUserMessageWall(userMessages, "userWallHome");
}


function showUserMessageWall(userMessages, panel) {
  let userWall = document.getElementById(panel);
  userWall.innerHTML = '<button type="button" class="refreshWallButton" onclick="refreshWallButtonClicked();">Refresh</button>' +
  '<div class="vertical"><h2>Messages wall</h2></div>';

  let messagesHTML = "";
  userMessages.forEach(function(message, idx){
    let author = message.author;
    let content = message.content.replaceAll("\n", "<br>");

    messagesHTML += "<h4>Author: " + author + "</h4>";
    messagesHTML += "<p>" + content + "</p>";
    if (idx != userMessages.length - 1) {
      messagesHTML += "<hr>";
    }
  });

  userWall.innerHTML += messagesHTML;
}

async function postButtonClicked() {
  let inHomePanel = document.getElementById("homePanel").style.display == "block";
  let viewedUser = inHomePanel ? "loggedInUserEmail" : "viewedSearchedUserEmail";

  let owner = localStorage.getItem(viewedUser);
  let author = localStorage.getItem("loggedInUserEmail");

  let newPostTextArea = inHomePanel ? "newPostTextAreaHome" : "newPostTextAreaBrowse";
  let messageText = document.getElementById(newPostTextArea).value;

  let postMessageDto = {
    "author" : author,
    "owner" : owner,
    "message" : messageText
  };

  let token = localStorage.getItem("token");

  if (messageText.length == 0){
    showErrors(["Empty posts not allowed!"]);
    return;
  }

  if (messageText.length > 1000) {
    showErrors(["Posts logner then 1000 characters not allowed!"]);
    return;
  }

  let message = JSON.stringify({
    "public_key": localStorage.getItem("loggedInUserEmail"),
    "method" : "POST",
    "URL" : "/message/post",
    "data" : postMessageDto
  });

  let hash = await sign_crypto(message + token, token);

  let response = await fetch('/message/post', {
    method: 'POST',
    headers: {
      'Authorization': hash,
      'Content-Type': 'application/json;charset=utf-8'
    },
    body: message
  });

  if (response.status === 400) {
    showErrors(["Something went wrong. Check if you are logged in."]);
  } else if (response.status === 401) {
    showErrors(["Your session expired. Please log in again"]);
    localStorage.removeItem("token");
    loadPage();
  } else if (response.status === 500) {
    showErrors(["Something went wrong."]);
  } else if (response.status === 201) {
    document.getElementById(newPostTextArea).value = "";
    refreshWallButtonClicked();
  } else {
    showErrors(["Something went wrong."]);
  }
}

// Browse Panel functions
async function searchUser(form){
  let email = form.emailSearched.value;
  let token = localStorage.getItem("token");
  let public_key = localStorage.getItem("loggedInUserEmail");

  let hash = await sign_crypto(public_key + token + 'GET' + '/get_user_data/' + email, token);

  let userDataResponse = await fetch('/get_user_data/' + email, {
    method: 'GET',
    headers: {
      'Authorization': hash,
      'Public-Key': public_key
    }
  });

  if (!userDataResponse.ok) {
    if (userDataResponse.status === 404) {
      showErrors(["User not found."]);
      return;
    }

    showErrors(["Something went wrong. Please log in again"]);
    localStorage.removeItem('token');
    loadPage();
  }

  hash = await sign_crypto(public_key + token + 'GET' + '/message/get/' + email, token);
  let userMessagesResponse = await fetch('/message/get/' + email, {
    method : "GET",
    headers: {
      'Authorization': hash,
      'Public-Key': public_key
    }
  });


  if (!userMessagesResponse.ok) {
    if (userMessagesResponse.status === 404) {
      showErrors(["User not found."]);
      return;
    }

    showErrors(["Something went wrong. Please log in again"]);
    localStorage.removeItem('token');
    loadPage();
  }

  let userData = await userDataResponse.json()
  let userMessages = await userMessagesResponse.json()

  localStorage.setItem("viewedSearchedUserEmail", userData.email);
  form.emailSearched.value = "";

  loadUserViewToBrowsePanel(userData, userMessages);
}

function loadUserViewToBrowsePanel(userData, userMessages) {
  document.getElementById("userPanel").innerHTML = document.getElementById("userHomeViewBrowse").innerHTML;

  document.getElementById("firstNameLabelBrowse").innerHTML = "Name: " + userData.first_name;
  document.getElementById("familyNameLabelBrowse").innerHTML = "Family Name: " + userData.family_name;
  document.getElementById("emailLabelBrowse").innerHTML = "Email: " + userData.email;
  document.getElementById("genderLabelBrowse").innerHTML = "Gender: " + userData.gender;
  document.getElementById("cityLabelBrowse").innerHTML = "City: " + userData.city;
  document.getElementById("countryLabelBrowse").innerHTML = "Country: " + userData.country;

  showUserMessageWall(userMessages, "userWallBrowse");
}

async function refreshWallButtonClicked() {
  let token = localStorage.getItem("token");
  let public_key = localStorage.getItem("loggedInUserEmail");

  let inHomePanel = document.getElementById("homePanel").style.display == "block";
  let panel = inHomePanel ? "userWallHome" : "userWallBrowse";
  let url = inHomePanel ? "/message/get" : "/message/get/" + localStorage.getItem("viewedSearchedUserEmail");

  let hash = await sign_crypto(public_key + token + 'GET' + url, token);

  let response = await fetch(url, {
    method: "GET",
    headers: {
      'Authorization': hash,
      'Public-Key': public_key
    }
  });

  if (!response.ok) {
    if (response.status === 404) {
      showErrors(["User not found."]);
      return;
    }

    showErrors(["Something went wrong. Please log in again"]);
    localStorage.removeItem('token');
    loadPage();
  }

  let userMessages = await response.json();
  showUserMessageWall(userMessages, panel);
}

async function submitChangePasswordForm(form) {
  document.getElementById("messagePasswordChange").innerHTML = "";

  if (!validateFormAndShowErrors(form)) {
    return;
  }

  let token = localStorage.getItem("token");
  let public_key = localStorage.getItem("loggedInUserEmail");

  let message = JSON.stringify({
    "public_key": localStorage.getItem("loggedInUserEmail"),
    "method": "PUT",
    "URL": "/change_password",
    "data": {
        "old_password": form.oldPassword.value,
        "new_password": form.newPassword.value
    }
  });

  let hach = sign_crypto(message + token, token);

  let response = await fetch('/change_password', {
    method: 'PUT',
    headers: {
      'Authorization': hush,
      'Content-Type': 'application/json;charset=utf-8'
    },
    body: message
  });

  if (!response.ok) {
    if (this.status == 401){
      showErrors(["Incorrect Password"]);
    } else {
      showErrors(["Something went wrong."]);
    }
    return;
  }

  form.oldPassword.value = "";
  form.newPassword.value = "";
  form.repeatPSW.value = "";
  document.getElementById("messagePasswordChange").innerHTML = "Password changed.";
  setTimeout(function(){
    document.getElementById("messagePasswordChange").innerHTML = "";
  }, 5000);
}

async function submitSignOut() {
  let token = localStorage.getItem("token");
  let public_key = localStorage.getItem("loggedInUserEmail");

  let hash = await sign_crypto(public_key + token + 'DELETE' + '/sign_out', token);

  let response = await fetch('/sign_out', {
    method: 'DELETE',
    headers: {
      'Authorization': hash,
      'Public-Key': public_key
    }
  });

  localStorage.removeItem('token');
  localStorage.removeItem('loggedInUserEmail');
  loadPage();
}

async function sign_crypto(message, key) {
  const getUtf8Bytes = str =>
    new Uint8Array(
      [...unescape(encodeURIComponent(str))].map(c => c.charCodeAt(0))
    );

  const keyBytes = getUtf8Bytes(key);
  const messageBytes = getUtf8Bytes(message);

  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' },
    true, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, messageBytes);

  // to lowercase hexits
  lower_hex = [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');

  return lower_hex;
}
