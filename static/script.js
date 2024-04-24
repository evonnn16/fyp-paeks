document.addEventListener('DOMContentLoaded', function() {
  var loc = ""+ window.location;
  var arr = loc.split('/');
  var page = arr[arr.length-1];

  if(page == "index.html" || page == ""){
    uid = localStorage.getItem('uid');
    if(uid == null || uid == "")
      window.location = "static/login.html";
  }
  else if(page == "create.html"){
    document.getElementById('from').value = localStorage.getItem('uid');
  }
  else if(page == "search.html"){
    document.querySelector(".result_holder").style.display = "none";
  }
  else if(page == "view.html"){
    eid = localStorage.getItem('eid');
    
    $.ajax({
      headers: { 
        'Accept': 'application/json',
        'Content-Type': 'application/json' 
      },
      type: "POST",
      url: "/view",
      data: JSON.stringify(eid),
      success: function(result) {
        // console.log("result:"+result);

        document.getElementById('subject').innerHTML = result.subject;
        document.getElementById('from').innerHTML = result.from;
        document.getElementById('date').innerHTML = result.date;
        document.getElementById('content').innerHTML = result.content;
      } 
    })
  }
  else if(page == "profile.html"){
    uid = localStorage.getItem('uid');

    $.ajax({
      headers: { 
        'Accept': 'application/json',
        'Content-Type': 'application/json' 
      },
      type: "POST",
      url: "/profile",
      data: JSON.stringify(uid),
      success: function(result) {
        // console.log("result:"+result);

        document.getElementById('username').innerHTML = result.username;
        document.getElementById('email').innerHTML = result.email;
      } 
    })
  }
})

function insert(){
  
  from = document.getElementById('from').value;
  to = document.getElementById('to').value;
  subject = document.getElementById('subject').value;
  keyword = document.getElementById('keyword').value;
  content = document.getElementById('content').value;
  
  if(from == "" || to == "" || subject == "" || keyword == "") return alert("Please fill in 'To', 'Subject' and 'Keyword'")
  
  d = new Date();
  date = d.getFullYear()+"-"+(d.getMonth()+1)+"-"+d.getDate()+" "+d.getHours()+":"+d.getMinutes()+":"+d.getSeconds();

  var data = [{
    "from": from,
    "to": to,
    "subject": subject,
    "keyword": keyword,
    "content": content,
    "date": date
  }];
  // console.log(data);

  $.ajax({
    headers: { 
      'Accept': 'application/json',
      'Content-Type': 'application/json' 
    },
    type: "POST",
    url: "/create",
    data: JSON.stringify(data),
    success: function(result) {
      alert(result);
    } 
  })
};

function search(){
  document.querySelector(".result_holder").style.display = "block";
  keyword = document.getElementById('keyword').value;
  uid = localStorage.getItem('uid');
  
  var data = [{
    "keyword": keyword,
    "uid": uid
  }];

  $.ajax({
    headers: { 
      'Accept': 'application/json',
      'Content-Type': 'application/json' 
    },
    type: "POST",
    url: "/search",
    data: JSON.stringify(data),
    success: function(result) {
      // console.log(result);
      // console.log(typeof result);

      var size = Object.keys(result).length;
      document.getElementById('no_result').innerHTML = size+" searching results";

      var data = "";

      Object.keys(result).forEach(key1 => {
        const value1 = result[key1];
        // console.log(`Email Key: ${key1}`);
        data += `<div class="result_row" id="`+key1+`" onclick='window.location = "view.html"; view("`+key1+`");'>
          <img src="image/user.png" alt="user">
          <p id="from">`+value1.from+`</p>
          <p id="subject">`+value1.subject+`</p>
          <p id="date">`+value1.date+`</p>
        </div>`;

        // Object.keys(value1).forEach(key2 => {
        //   const value2 = value1[key2];
        //   console.log(`Content Key: ${key2}, Value: ${value2}`);
        // })
      });
      document.getElementById('result_list').innerHTML = data;
    } 
  })
}

function view(eid){
  window.location = "view.html";
  localStorage.setItem('eid', eid);
}

function register(){
  username = document.getElementById('username').value;
  email = document.getElementById('email').value;
  pwd = document.getElementById('pwd').value;
  pwd2 = document.getElementById('pwd2').value;
  
  if(username=="" || pwd == "" || pwd2 == "" || email == "") return alert("Please fill in all inputs")

  if(pwd != pwd2)
    alert("Passwords not matched!")
  else{
    if(!email.includes("@paeks.mail.com")){
      email = email.split("@")[0]+"@paeks.mail.com";
    }

    var data = [{
      "username": username,
      "email": email,
      "pwd": pwd
    }];
  
    $.ajax({
      headers: { 
        'Accept': 'application/json',
        'Content-Type': 'application/json' 
      },
      type: "POST",
      url: "/register",
      data: JSON.stringify(data),
      success: function(result) {
        if(result == "success") window.location = "login.html";
        else alert(result);
      } 
    })
  }
}

function login(){
  email = document.getElementById('email').value;
  pwd = document.getElementById('pwd').value;
  
  if(pwd == "" || email == "") return alert("Please fill in Email Address and Password")
  if(!email.includes("@paeks.mail.com")){
      email = email.split("@")[0]+"@paeks.mail.com";
  }

  var data = [{
    "email": email,
    "pwd": pwd
  }];
  // console.log(data);

  $.ajax({
    headers: { 
      'Accept': 'application/json',
      'Content-Type': 'application/json' 
    },
    type: "POST",
    url: "/login",
    data: JSON.stringify(data),
    success: function(result) {
      //console.log("server response:"+result);
      if(result == "success"){
        localStorage.setItem('uid', email);
        window.location = "/";
      } 
      if(result == "0") alert("fail login: account not found or password is wrong")
      //else{
      //  localStorage.setItem('uid', result);
      //  window.location = "/";
      //}
    } 
  })
}

function logout(){
  localStorage.setItem('uid', "");
  window.location = "login.html";
}
