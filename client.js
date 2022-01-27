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

function submitSignUpForm(form) {
  if (!validateFormAndShowErrors(form)) {
    return;
  }

  signUpDto = {
    "email": form.email.value,
    "password": form.newPassword.value,
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
  tabClicked("home");

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

    loadUserViewToHomePanel(userDataResult.data, userMessagesResult.data, "homePanel");
  }
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
  document.getElementById("homeTab").style.color = "blue";
  document.getElementById("browseTab").style.color = "blue";
  document.getElementById("accountTab").style.color = "blue";

  document.getElementById(name).style.color = "maroon";
}

function loadUserViewToHomePanel(userData, userMessages) {
  document.getElementById("homePanel").innerHTML = document.getElementById("userHomeView").innerHTML;

  document.getElementById("firstNameLabel").innerHTML = "Name: " + userData.firstname;
  document.getElementById("familyNameLabel").innerHTML = "Family Name: " + userData.familyname;
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
  let inHomePanel = document.getElementById("homePanel").style.display == "block";
  let viewedUser = inHomePanel ? "viewedUserEmail" : "viewedSearchedUserEmail";
  let newPostTextArea = inHomePanel ? "newPostTextAreaHome" : "newPostTextAreaBrowse";
  let token = localStorage.getItem("token");
  let email = localStorage.getItem(viewedUser);
  let message = document.getElementById(newPostTextArea).value;

  if (message.length == 0){
    showErrors(["Empty posts not allowed!"]);
    return;
  }

  let result = serverstub.postMessage(token, message, email);

  if (!result.success){
    showErrors([result.message]);
  }else{
    document.getElementById(newPostTextArea).value = "";
    refreshWallButtonClicked();
  }
}

// Browse Panel functions
function searchUser(form){
  let email = form.emailSearched.value;
  let token = localStorage.getItem("token");
  let userDataResult = serverstub.getUserDataByEmail(token, email);
  let userMessagesResult = serverstub.getUserMessagesByEmail(token, email);

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
    localStorage.setItem("viewedSearchedUserEmail", userDataResult.data.email);
    form.emailSearched.value = "";

    loadUserViewToBrowsePanel(userDataResult.data, userMessagesResult.data);
  }
}

function loadUserViewToBrowsePanel(userData, userMessages) {
  document.getElementById("userPanel").innerHTML = document.getElementById("userHomeViewBrowse").innerHTML;

  document.getElementById("firstNameLabelBrowse").innerHTML = "Name: " + userData.firstname;
  document.getElementById("familyNameLabelBrowse").innerHTML = "Family Name: " + userData.familyname;
  document.getElementById("emailLabelBrowse").innerHTML = "Email: " + userData.email;
  document.getElementById("genderLabelBrowse").innerHTML = "Gender: " + userData.gender;
  document.getElementById("cityLabelBrowse").innerHTML = "City: " + userData.city;
  document.getElementById("countryLabelBrowse").innerHTML = "Country: " + userData.country;

  showUserMessageWall(userMessages, "userWallBrowse");
}

function refreshWallButtonClicked() {
  let token = localStorage.getItem("token");
  let inHomePanel = document.getElementById("homePanel").style.display == "block";
  let panel = inHomePanel ? "userWallHome" : "userWallBrowse";
  let userMessagesResult = serverstub.getUserMessagesByToken(token);
  if (!inHomePanel){
    let email = localStorage.getItem("viewedSearchedUserEmail");
    userMessagesResult = serverstub.getUserMessagesByEmail(token, email);
  }

  if (!userMessagesResult.success){
    showErrors([userMessagesResult.message]);
  }else{
    showUserMessageWall(userMessagesResult.data, panel);
  }
}

function submitChangePasswordForm(form) {
  document.getElementById("messagePasswordChange").innerHTML = "";
  let oldPassword = form.oldPassword.value;
  let newPassword = form.newPassword.value;
  let repeatPSW = form.repeatPSW.value;

  let token = localStorage.getItem("token");

  if (!validateFormAndShowErrors(form)) {
    return;
  }
  let passwordChangeResult = serverstub.changePassword(token, oldPassword, newPassword);
  if (!passwordChangeResult.success){
    showErrors([passwordChangeResult.message]);
  } else if (!validateFormAndShowErrors(form)) {
    return;
  } else {
    form.oldPassword.value = "";
    form.newPassword.value = "";
    form.repeatPSW.value = "";
    document.getElementById("messagePasswordChange").innerHTML = passwordChangeResult.message;

    setTimeout(function(){
      document.getElementById("messagePasswordChange").innerHTML = "";
    }, 5000);
  };
}

function submitSignOut() {
  let token = localStorage.getItem("token");
  let signOutResult = serverstub.signOut(token);
  if (!signOutResult.success){
    showErrors([signOutResult.message]);
  } else {
    localStorage.removeItem("token");
    loadPage();
  };
}
