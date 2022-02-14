window.onload = function(){
  loadPage();
}

// GENERAL FUCTIONS
let connection = null;
function webSocketConnection(token){
  if connection != null){
    try{
      connection.close();
    }
    catch (error){
      console.log(error);
    }
  }
  connection = new WebSocket("ws://" + window.location.hostname + ":5000/api");

  let connection_object = {
    "type": "connection_open",
    "token": token
  }
  connection.onopen = function(){
    connection.send(JSON.stringify(connection_object));
  }; //or setting a cookie?

  connection.onclose = function(){
    submitSignOut(); // maybe we dont want to do this because when sever reboots we sign out as well
  };
}

function loadPage() {
  let pageContent = document.getElementById("pageContent");
  let token = localStorage.getItem("token");

  if (token != null) {
    // signed in so connecting to web socket and loading user home page
    webSocketConnection(token);

    let content = document.getElementById("profileView").innerHTML;
    pageContent.innerHTML = content;
    homeTabClicked();
  } else {
    let content = document.getElementById("welcomeView").innerHTML;
    pageContent.innerHTML = content;
  }
}

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

function submitSignUpForm(form) {
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

  let request = new XMLHttpRequest();
  request.open('POST', '/sign_up', true);
  request.setRequestHeader("Content-Type", "application/json;charset=utf-8");
  request.onreadystatechange = function() {
    if (request.readyState !== 4) {
      return;
    }

    if (request.status === 400) {
      showErrors(["Invalid input."]);
    } else if (request.status === 409) {
      showErrors(["User already exists."]);
    } else if (request.status === 500) {
      showErrors(["Something went wrong."]);
    } else if (request.status === 201) {
      let username = signUpDto.email;
      let password = signUpDto.password;

      signIn(username, password);
    } else {
      showErrors(["Something went wrong."]);
    }
  }
  request.send(JSON.stringify(signUpDto));
};

function submitSignInForm(form) {
  let username = form.emailLogin.value;
  let password = form.password.value;

  signIn(username, password);
};

function signIn(username, password){
  let signInDto = {"username" : username, "password" : password}

  let request = new XMLHttpRequest();
  request.open('POST', '/sign_in', true);
  request.setRequestHeader("Content-Type", "application/json;charset=utf-8");
  request.onreadystatechange = function() {
    if (request.readyState !== 4) {
      return;
    }

    if (request.status === 400) {
      showErrors(["The username or password are missing."]);
    //} else if (request.status === 409) {
      //showErrors(["User already logged in."]);
    } else if (request.status ===  404) {
      showErrors(["No such user"]);
    } else if (request.status ===  403) {
      showErrors(["Wrong password."]);
    } else if (request.status === 500) {
      showErrors(["Something went wrong."]);
    } else if (request.status === 200) {
      result = JSON.parse(request.responseText);
      localStorage.setItem("token", result.token);

      loadPage();
    } else {
      showErrors(["Something went wrong."]);
    }
  }

  request.send(JSON.stringify(signInDto));
}

// MAIN PAGE FUNCITONS

function homeTabClicked() {
  tabClicked("home");

  let token = localStorage.getItem("token");

  // First send user data request
  let userDataRequest = new XMLHttpRequest();
  userDataRequest.open('GET', '/get_user_data_by_token', true);
  userDataRequest.setRequestHeader('Authorization', token);
  userDataRequest.onreadystatechange = function() {
    if (userDataRequest.readyState !== 4) {
      return;
    }

    if (userDataRequest.status === 400) {
      showErrors(["Something went wrong. Please check if you are logged in."]);
    } else if (userDataRequest.status === 401) {
      showErrors(["Your session expired. Please log in again."]);
      localStorage.removeItem("token");
    } else if (userDataRequest.status === 200) {
      let userData = JSON.parse(userDataRequest.responseText);

      // When user data request is successful, send user wall messages request
      let userMessagesRequest = new XMLHttpRequest();
      userMessagesRequest.open('GET', '/message/get', true);
      userMessagesRequest.setRequestHeader('Authorization', token);
      userMessagesRequest.onreadystatechange = function() {
        if (userMessagesRequest.readyState !== 4) {
          return;
        }

        if (userMessagesRequest.status === 400) {
          showErrors(["Something went wrong. Please check if you are logged in."]);
        } else if (userMessagesRequest.status === 401) {
          showErrors(["Your session expired. Please log in again."]);
          localStorage.removeItem("token");
        } else if (userMessagesRequest.status === 200) {
          let userMessages = JSON.parse(userMessagesRequest.responseText);

          // When all requests are successful, show home panel
          localStorage.setItem("viewedUserEmail", userData.email);
          loadUserViewToHomePanel(userData, userMessages, "homePanel");
        } else {
          showErrors(["Something went wrong."]);
        }
      }
      userMessagesRequest.send();
    } else {
      showErrors(["Something went wrong."]);
    }
  }
  userDataRequest.send();
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

function postButtonClicked() {
  let inHomePanel = document.getElementById("homePanel").style.display == "block";
  let viewedUser = inHomePanel ? "viewedUserEmail" : "viewedSearchedUserEmail";

  let owner = localStorage.getItem(viewedUser);
  let author = localStorage.getItem("viewedUserEmail");

  let newPostTextArea = inHomePanel ? "newPostTextAreaHome" : "newPostTextAreaBrowse";
  let message = document.getElementById(newPostTextArea).value;

  let postMessageDto = {
    "author" : author,
    "owner" : owner,
    "message" : message
  };

  let token = localStorage.getItem("token");

  if (message.length == 0){
    showErrors(["Empty posts not allowed!"]);
    return;
  }

  if (message.length > 1000) {
    showErrors(["Posts logner then 1000 characters not allowed!"]);
    return;
  }

  let request = new XMLHttpRequest();
  request.open('POST', '/message/post', true);
  request.setRequestHeader('Content-Type', 'application/json;encoding=utf-8');
  request.setRequestHeader('Authorization', token);
  request.onreadystatechange = function() {
    if (request.readyState !== 4) {
      return;
    }

    if (request.status === 400) {
      showErrors(["Something went wrong. Check if you are logged in."]);
    } else if (request.status === 401) {
      showErrors(["Your session expired. Please log in again"]);
      localStorage.removeItem("token");
    } else if (request.status === 500) {
      showErrors(["Something went wrong."]);
    } else if (request.status === 201) {
      document.getElementById(newPostTextArea).value = "";
      refreshWallButtonClicked();
    } else {
      showErrors(["Something went wrong."]);
    }
  }
  request.send(JSON.stringify(postMessageDto));
}

// Browse Panel functions
function searchUser(form){
  let email = form.emailSearched.value;
  let token = localStorage.getItem("token");

  // First send user data request
  let userDataRequest = new XMLHttpRequest();
  userDataRequest.open('GET', '/get_user_data/' + email, true);
  userDataRequest.setRequestHeader('Authorization', token);
  userDataRequest.onreadystatechange = function() {
    if (userDataRequest.readyState !== 4) {
      return;
    }

    if (userDataRequest.status === 400) {
      showErrors(["Something went wrong. Please check if you are logged in."]);
    } else if (userDataRequest.status === 401) {
      showErrors(["Your session expired. Please log in again."]);
      localStorage.removeItem("token");
    } else if (userDataRequest.status === 404) {
      showErrors(["User not found."]);
    } else if (userDataRequest.status === 200) {
      let userData = JSON.parse(userDataRequest.responseText);

      // When user data request is successful, send user wall messages request
      let userMessagesRequest = new XMLHttpRequest();
      userMessagesRequest.open('GET', '/message/get/' + email, true);
      userMessagesRequest.setRequestHeader('Authorization', token);
      userMessagesRequest.onreadystatechange = function() {
        if (userMessagesRequest.readyState !== 4) {
          return;
        }

        if (userMessagesRequest.status === 400) {
          showErrors(["Something went wrong. Please check if you are logged in."]);
        } else if (userMessagesRequest.status === 401) {
          showErrors(["Your session expired. Please log in again."]);
          localStorage.removeItem("token");
        } else if (userMessagesRequest.status === 404) {
          showErrors(["User not found."]);
        } else if (userMessagesRequest.status === 200) {
          let userMessages = JSON.parse(userMessagesRequest.responseText);

          // When all requests are successful, show user panel
          localStorage.setItem("viewedSearchedUserEmail", userData.email);
          form.emailSearched.value = "";

          loadUserViewToBrowsePanel(userData, userMessages);
        } else {
          showErrors(["Something went wrong."]);
        }
      }
      userMessagesRequest.send();
    } else {
      showErrors(["Something went wrong."]);
    }
  }
  userDataRequest.send();
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

function refreshWallButtonClicked() {
  let token = localStorage.getItem("token");
  let inHomePanel = document.getElementById("homePanel").style.display == "block";
  let panel = inHomePanel ? "userWallHome" : "userWallBrowse";


  let request = new XMLHttpRequest();
  if (inHomePanel) {
    request.open("GET", "/message/get", true);
  } else {
    let searchedUserEmail = localStorage.getItem("viewedSearchedUserEmail");
    request.open("GET", "/message/get/" + searchedUserEmail, true);
  }
  request.setRequestHeader("Authorization", token);

  request.onreadystatechange = function(){
    if (this.readyState !== 4){
      return;
    }

    if (request.status === 400) {
      showErrors(["Something went wrong. Please check if you are logged in."]);
    } else if (request.status === 401) {
      showErrors(["Your session expired. Please log in again."]);
      localStorage.removeItem("token");
    } else if (request.status === 404) {
      showErrors(["User not found."]);
    } else if (request.status === 200) {
      let userMessages = JSON.parse(request.responseText);

      showUserMessageWall(userMessages, panel);
    } else {
      showErrors(["Something went wrong."]);
    }
  }
  request.send();
}

function submitChangePasswordForm(form) {
  document.getElementById("messagePasswordChange").innerHTML = "";

  let changePasswordDto = {
    "old_password": form.oldPassword.value,
    "new_password": form.newPassword.value
  }

  if (!validateFormAndShowErrors(form)) {
    return;
  }

  let token = localStorage.getItem("token");

  let request = new XMLHttpRequest();
  request.open("PUT", "/change_password", true);
  request.setRequestHeader("Authorization", token);
  request.setRequestHeader("Content-Type", "application/json;encoding=UTF-8");

  request.onreadystatechange = function(){
    if (this.readyState == 4){
      if (this.status == 200) {
        form.oldPassword.value = "";
        form.newPassword.value = "";
        form.repeatPSW.value = "";
        document.getElementById("messagePasswordChange").innerHTML = "Password changed.";
        setTimeout(function(){
          document.getElementById("messagePasswordChange").innerHTML = "";
        }, 5000);
      } else if (this.status == 401){
        showErrors(["You are not logged in."]);
        localStorage.removeItem("token");
      } else if (this.status == 403){
        showErrors(["Wrong password."]);
      } else {
        showErrors(["Something went wrong."]);
      }
    } else {
      return;
    }
  }

  request.send(JSON.stringify(changePasswordDto))
}

function submitSignOut() {
  let token = localStorage.getItem("token");
  let request = new XMLHttpRequest();
  request.open("DELETE", "/sign_out", true);
  request.setRequestHeader("Authorization", token);
  request.onreadystatechange = function(){
    if (request.readyState !== 4 ) {
      return;
    }

    if (this.status == 401){
      showErrors(["You are not signed in."]);
      localStorage.removeItem("token");
    } else if (request.status == 200){
      token = localStorage.getItem("token");
      username = localStorage.getItem("viewedUserEmail")

      localStorage.removeItem("token");

      let sign_out_event = {
        "type" : "sign_out",
        "token" : token,
        "username" : username
      }
      connection.send(JSON.stringify(sign_out_event))

      loadPage();
    } else {
      showErrors(["Something went wrong."]);
    }
  }
  request.send();
}
