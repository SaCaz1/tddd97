displayView = function(){
  //code
};

window.onload = function(){
  loadPage();
};

function loadPage() {
  let pageContent = document.getElementById("pageContent");
  let token = localStorage.getItem("token");

  if (token != null) {
    let content = document.getElementById("profileView").innerHTML;
    pageContent.innerHTML = content;
  } else {
    let content = document.getElementById("welcomeView").innerHTML;
    pageContent.innerHTML = content;
  };
};


function tabClicked(panelName) {
  document.getElementById("homePanel").style.display = "none";
  document.getElementById("browsePanel").style.display = "none";
  document.getElementById("accountPanel").style.display = "none";

  document.getElementById(panelName).style.display = "block";
};

// function setEventListeners() {
//   let homeTab = document.getElementById("homeTab");
//   homeTab.addEventListener("click", function() {
//     document.getElementById("homePanel").style.display = "block";
//     document.getElementById("browsePanel").style.display = "none";
//     document.getElementById("accountPanel").style.display = "none";
//   });
//
// };

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
    let content = document.getElementById("profileView").innerHTML;
    let pageContent = document.getElementById("pageContent");
    pageContent.innerHTML = content;
  }
  else {
    document.getElementById("serverMessage").innerHTML = result.message;
  };
};

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

function submitSignInForm(form) {
    console.log("Hello");

  let username = form.email.value;
  let password = form.password.value;

  console.log(username, password);

  let result = serverstub.signIn(username, password);

  console.log(result);

  if (result.success) {
    localStorage.setItem("token", result.data);

    loadPage();
  }
  else {
    document.getElementById("loginError").innerHTML = "<p>"+ result.message +"</p>";
  };
};
