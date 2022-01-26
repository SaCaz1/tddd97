window.onload = function(){
  loadPage();
}

// GENERAL FUCTIONS

function loadPage() {
  let pageContent = document.getElementById("pageContent");
  let token = localStorage.getItem("token");

  if (token != null) {
    let content = document.getElementById("profileView").innerHTML;
    pageContent.innerHTML = content;
    homeTabClicked();
  } else {
    let content = document.getElementById("welcomeView").innerHTML;
    pageContent.innerHTML = content;
  }
}

function showErrors(errorMessages){
  errorMessageBlock = document.getElementById("errorMessage")
  errorMessageBlock.innerHTML = "";

  errorMessages.forEach(function(message){
    errorMessageBlock.innerHTML += '<p>' + message + "</p>";
  });

  setTimeout(function(){
    errorMessageBlock.innerHTML = "";
  }, 5000);
}

// WELCOME VIEW FUNCTONS

function validateFormAndShowErrors(form) {
  let password = form.password;
  let repeat = form.repeatPSW;

  if (password.value != repeat.value) {
    repeat.setCustomValidity("Repeating password does not match!");
    repeat.reportValidity();
    return false;
  }

  password.setCustomValidity("");
  return true;
};

function submitSignUpForm(form) {
  if (!validateFormAndShowErrors(form)) {
    return;
  }

  signUpDto = {
    "email": form.email.value,
    "password": form.password.value,
    "firstname": form.firstName.value,
    "familyname": form.familyName.value,
    "gender": form.gender.value,
    "city": form.city.value,
    "country": form.country.value
  };

  let result = serverstub.signUp(signUpDto);

  if (result.success) {
    let username = signUpDto.email;
    let password = signUpDto.password;

    signIn(username, password);
  }
  else {
    showErrors([result.message]);
  }
};

function submitSignInForm(form) {
  let username = form.email.value;
  let password = form.password.value;

  signIn(username, password);
};

function signIn(username, password){
  let result = serverstub.signIn(username, password);

  if (result.success) {
    localStorage.setItem("token", result.data);

    loadPage();
  }else {
    showErrors([result.message]);
  }
}

// MAIN PAGE FUNCITONS

function homeTabClicked() {
  setVisiblePanel("homePanel");
  setSelectedTab("homeTab");

  let token = localStorage.getItem("token");
  let userDataResult = serverstub.getUserDataByToken(token);
  let userMessagesResult = serverstub.getUserMessagesByToken(token);

  let errorMessages = [];
  if (!userDataResult.success){
    errorMessages.push(userDataResult.message);
  }
  if (!userMessagesResult.success){
    errorMessages.push(userDataResult.message);
  }

  if (errorMessages.length > 0) {
    showErrors(errorMessages);
  }else {
    localStorage.setItem("viewedUserEmail", userDataResult.data.email);

    loadUserViewToPanel(userDataResult.data, userMessagesResult.data, "homePanel");
  }
}

function setVisiblePanel(name) {
  document.getElementById("homePanel").style.display = "none";
  document.getElementById("browsePanel").style.display = "none";
  document.getElementById("accountPanel").style.display = "none";

  document.getElementById(name).style.display = "block";
}

function setSelectedTab(name) {
  document.getElementById("homeTab").style.color = "blue";
  document.getElementById("browseTab").style.color = "blue";
  document.getElementById("accountTab").style.color = "blue";

  document.getElementById(name).style.color = "maroon";
}

function loadUserViewToPanel(userData, userMessages, panel) {
  document.getElementById(panel).innerHTML = document.getElementById("userHomeView").innerHTML;

  document.getElementById("firstNameLabel").innerHTML = "Name: " + userData.firstname;
  document.getElementById("familyNameLabel").innerHTML = "Family Name: " + userData.familyname;
  document.getElementById("emailLabel").innerHTML = "Email: " + userData.email;
  document.getElementById("genderLabel").innerHTML = "Gender: " + userData.gender;
  document.getElementById("cityLabel").innerHTML = "City: " + userData.city;
  document.getElementById("countryLabel").innerHTML = "Country: " + userData.country;

  showUserMessageWall(userMessages);
}

function showUserMessageWall(userMessages) {
  let userWall = document.getElementById("userWall");
  userWall.innerHTML = '<button type="button" id="refreshWallButton" onclick="refreshWallButtonClicked();">Refresh</button>' +
  '<div class="vertical"><h2>Messages wall</h2></div>';

  let messagesHTML = "";
  userMessages.forEach(function(message, idx){
    let author = message.writer;
    let content = message.content.replaceAll("\n", "<br>");

    messagesHTML += "<h4>Author: " + author + "</h4>";
    messagesHTML += "<p>" + content + "</p>";
    if (idx != userMessages.length - 1) {
      messagesHTML += "<hr>";
    }
  });

  userWall.innerHTML += messagesHTML;
}

function postButtonClicked() {
  let token = localStorage.getItem("token");
  let email = localStorage.getItem("viewedUserEmail");
  let message = document.getElementById("newPostTextArea").value;

  if (message.length == 0){
    showErrors(["Empty posts not allowed!"]);
    return;
  }

  let result = serverstub.postMessage(token, message, email);

  if (!result.success){
    showErrors([result.message]);
  }else{
    document.getElementById("newPostTextArea").value = "";
    refreshWallButtonClicked();
  }
}

// this one should be more generic to work in browse view
function refreshWallButtonClicked() {
  let token = localStorage.getItem("token");
  let userMessagesResult = serverstub.getUserMessagesByToken(token);

  if (!userMessagesResult.success){
    showErrors([userMessagesResult.message]);
  }else{
    showUserMessageWall(userMessagesResult.data);
  }
}
