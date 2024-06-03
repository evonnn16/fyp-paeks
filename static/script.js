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
    $.ajax({
      headers: { 
        'Accept': 'application/json',
        'Content-Type': 'application/json' 
      },
      type: "POST",
      url: "/profile",
      data: JSON.stringify(localStorage.getItem('uid')),
      success: function(result) {
        // console.log("result:"+result);
	if(result.status === "success"){
          document.getElementById('from').value = result.email;
        }else alert("Error retrieving user email")
      }
    })
  }
  else if(page == "search.html"){
    document.querySelector(".result_holder").style.display = "none";
    document.getElementById("view_container").style.display = "none";
  }
  else if(page == "profile.html"){
    $.ajax({
      headers: { 
        'Accept': 'application/json',
        'Content-Type': 'application/json' 
      },
      type: "POST",
      url: "/profile",
      data: JSON.stringify(localStorage.getItem('uid')),
      success: function(result) {
        // console.log("result:"+result);
	if(result.status === "success"){
          document.getElementById('username').innerHTML = result.username;
          document.getElementById('email').innerHTML = result.email;
        }else alert("Error retrieving user profile")
      }
    })
  }
  else if(page =="register.html"){
    $('#loading').hide();
  }
})

function register(){
  username = document.getElementById('username').value;
  email = document.getElementById('email').value;
  pwd = document.getElementById('pwd').value;
  pwd2 = document.getElementById('pwd2').value;
  
  if(username=="" || pwd == "" || pwd2 == "" || email == "") return alert("Please fill in all information")

  if(pwd != pwd2)
    alert("Passwords are not matched")
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
      beforeSend: function(){
        $('#loading').show();
      },
      complete: function(){
        $('#loading').hide();
      },
      success: function(result) {
        if(result.status === "success"){
          window.location = "login.html";
        } else if (result.status === "fail") {
          alert("Fail registration: " + result.msg);
        } else {
          console.error("Unexpected response:", result);
          alert("Unexpected response from server. Please try again later.");
        }
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
      if(result.status === "success"){
        localStorage.setItem('uid', result.uid);
        window.location = "/";
      } else if (result.status === "fail") {
        alert("Fail login: " + result.msg);
      } else {
        console.error("Unexpected response:", result);
        alert("Unexpected response from server. Please try again later.");
      }
    } 
  })
}

function logout(){
  localStorage.setItem('uid', "");
  window.location = "login.html";
}

function insert(){  
  from = localStorage.getItem('uid');
  to = document.getElementById('to').value;
  subject = document.getElementById('subject').value;
  keyword = document.getElementById('keyword').value;
  content = document.getElementById('content').value;
  
  if(from == "" || to == "" || subject == "" || keyword == "") return alert("Please fill in 'To', 'Subject' and 'Keyword'")
  
  d = new Date();
  date = d.getFullYear()+"-"+(d.getMonth()+1).toString().padStart(2, '0')+"-"+d.getDate().toString().padStart(2, '0')+" "+d.getHours().toString().padStart(2, '0')+":"+d.getMinutes().toString().padStart(2, '0')+":"+d.getSeconds().toString().padStart(2, '0');

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
      if(result.status === "success"){
        alert(result.msg);
        window.location = "/";
      } else if (result.status === "fail") {
        alert("Fail sending: " + result.msg);
      } else {
        console.error("Unexpected response:", result);
        alert("Unexpected response from server. Please try again later.");
      }
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
      if(result.status === "success"){
        let entries = Object.entries(result.data);      
        entries.sort((a, b) => {
          const dateA = new Date(a[1].date);
          const dateB = new Date(b[1].date);
          return dateB - dateA; // descending order
        });
        //console.log(entries); //[[eid,obj],[eid,obj]]      
        result.data = Object.fromEntries(entries);
        //console.log(result);
	    
        var size = Object.keys(result.data).length;
        document.getElementById('no_result').innerHTML = size+" searching results";
	    
        var data = "";
	    
        Object.keys(result.data).forEach(key1 => {
          const value1 = result.data[key1];
          
          data += `<div class="result_row" id="`+key1+`" onclick='view("`+key1+`");'>
            <img src="image/user2.png" alt="user">
            <p id="username">`+value1.username+`</p>
            <p id="from" hidden>`+value1.from+`</p>
            <p id="subject">`+value1.subject+`</p>
            <p id="date">`+value1.date+`</p>
            <p id="content" hidden>`+value1.content.replace(/\n/g, '<br>')+`</p>
          </div>`;
        });
        document.getElementById('result_list').innerHTML = data;
      } else if (result.status === "fail") {
        alert("Fail sending: " + result.msg);
      } else {
        console.error("Unexpected response:", result);
        alert("Unexpected response from server. Please try again later.");
      }     
      
    } 
  })
}

function view(eid){  
  document.getElementById('search_main').style.display = 'none';
  document.getElementById('view_container').style.display = 'block';
    
  document.getElementById('vusername').innerHTML = document.getElementById(eid).querySelector("#username").innerHTML;
  document.getElementById('vsubject').innerHTML = document.getElementById(eid).querySelector("#subject").innerHTML;
  document.getElementById('vfrom').innerHTML = document.getElementById(eid).querySelector("#from").innerHTML;
  document.getElementById('vdate').innerHTML = document.getElementById(eid).querySelector("#date").innerHTML;
  document.getElementById('vcontent').innerHTML = document.getElementById(eid).querySelector("#content").innerHTML;
}

function goback(){
  document.getElementById('search_main').style.display = 'inline-grid';
  document.getElementById('view_container').style.display = 'none';
}

