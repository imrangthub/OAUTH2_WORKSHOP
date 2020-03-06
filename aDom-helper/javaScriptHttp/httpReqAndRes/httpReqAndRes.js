

const getReqBtn = document.getElementById('getReqBtn');
const postReqBtn = document.getElementById('postReqBtn');
const postReqBtnRaw = document.getElementById('postReqBtnRaw');




const getDataReq = () => {
  console.log("getDataReq: Url: "+document.getElementById("getUrlValue").value);
  makeHttpRequest('GET', document.getElementById("getUrlValue").value, {}).then(resData => {
    console.log("RES# ", resData);
  })
  .catch(err => {
    console.log(err);
  });
}

const postDataReq = () => {
  console.log("postDataReq: Url: "+document.getElementById("postUrlValue").value);
  makeHttpRequest('POST', document.getElementById("postUrlValue").value, {
    id: 101,
    name: 'MD IMRAN HOSSAIN',
    gender: 'Male'
  }).then(resData => {
    console.log("RES# ", resData);
  });
}




const postDataReqRaw = () => {
	  console.log("Raw : Url: "+document.getElementById("rawUrlValue").value);
  const xhr = new XMLHttpRequest();
  xhr.open('POST', document.getElementById("rawUrlValue").value)

  xhr.setRequestHeader('simple-Msg', 'This is a Sample Message in Header');
  xhr.setRequestHeader('my-auth-token', '123456');
  xhr.setRequestHeader('Content-Type', 'application/json');

  xhr.responseType = 'json';
  xhr.onload = () => {
    const resData = xhr.response;
    console.log("POST REQ RAW RES# ", resData);
  }

  xhr.send();
}


getReqBtn.addEventListener('click', getDataReq);
postReqBtn.addEventListener('click', postDataReq);
postReqBtnRaw.addEventListener('click', postDataReqRaw);

const makeHttpRequest = (method, url, data) => {

  const reqPromise = new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open(method, url)
    xhr.responseType = 'json';
    if (data) {
      xhr.setRequestHeader('Content-Type', 'application/json');
    }
    xhr.onload = () => {
      if(xhr.status >= 400){
         reject(xhr.response);
      }
      resolve(xhr.response);
    }
    xhr.onerror = () => {
      reject("Technical Error found !");
    }

    xhr.send(JSON.stringify(data));
  });

  return reqPromise;
}

