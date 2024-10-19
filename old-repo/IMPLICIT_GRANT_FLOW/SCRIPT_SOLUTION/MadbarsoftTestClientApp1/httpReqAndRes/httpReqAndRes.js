

const getReqBtn = document.getElementById('getReqBtn');

const getResValue = document.getElementById('getResValue');


const getDataReq = () => {
  console.log("getDataReq: Url: "+document.getElementById("getUrlValue").value);
  if(!document.getElementById("getUrlValue").value){
    alert("No Url found");
    return;
  }
  makeHttpRequest('GET', document.getElementById("getUrlValue").value, {}).then(resData => {
    console.log("RES# ", resData);
    $('#resultSuccessMsg').text('Success');
    $('#resultErrMsg').text('');
    $('#getResValue').val(JSON.stringify(resData));
  })
  .catch(err => {
    $('#resultErrMsg').text('Error');
    $('#resultSuccessMsg').text('');
    $('#getResValue').val('');
    $('#getResValue').val(JSON.stringify(err));
    console.log(err);
  });
}

getReqBtn.addEventListener('click', getDataReq);


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

