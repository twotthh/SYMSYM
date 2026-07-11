// 1. 페이지가 열리면 먼저 로그인 상태인지 확인
document.addEventListener('DOMContentLoaded', () => {
    chrome.storage.local.get(['userEmail'], (result) => {
        if (result.userEmail) {
            // 1-1. 로그인 기록이 있으면 메인 화면으로
            showMainSection(result.userEmail);
        }
    });
});

function showMainSection(email) {
    document.getElementById('auth-section').style.display = 'none';
    document.getElementById('main-section').style.display = 'block';
    document.getElementById('logoutBtn').style.display = 'block';
    document.getElementById('emailInput').value = email;
}

// 2. 회원가입 버튼 로직
document.getElementById('registerBtn').addEventListener('click', async () => {
    const email = document.getElementById('authEmail').value.trim();
    const password = document.getElementById('authPassword').value.trim();
    const msgBox = document.getElementById('authMessage');

    if (!email || !password) return msgBox.innerText = "이메일과 비밀번호를 모두 입력해주세요.";

    try {
        const response = await fetch('http://127.0.0.1:8000/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const data = await response.json();
        
        if (response.ok) {
            msgBox.style.color = "#9DAD71"; 
            msgBox.innerText = "가입 성공! 이제 로그인해주세요.";
        } else {
            msgBox.style.color = "#E38792";
            msgBox.innerText = data.detail;
        }
    } catch (err) {
        msgBox.innerText = "서버 연결 실패.";
    }
});

// 3. 로그인 버튼 로직
document.getElementById('loginBtn').addEventListener('click', async () => {
    const email = document.getElementById('authEmail').value.trim();
    const password = document.getElementById('authPassword').value.trim();
    const msgBox = document.getElementById('authMessage');

    if (!email || !password) return msgBox.innerText = "이메일과 비밀번호를 모두 입력해주세요.";

    try {
        const response = await fetch('http://127.0.0.1:8000/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const data = await response.json();
        
        if (response.ok) {
            chrome.storage.local.set({ userEmail: data.email }, () => {
                showMainSection(data.email);
            });
        } else {
            msgBox.style.color = "#E38792";
            msgBox.innerText = data.detail;
        }
    } catch (err) {
        msgBox.innerText = "서버 연결 실패.";
    }
});

// 4. 로그아웃 버튼 로직
document.getElementById('logoutBtn').addEventListener('click', () => {
    chrome.storage.local.remove(['userEmail'], () => {
        document.getElementById('auth-section').style.display = 'block';
        document.getElementById('main-section').style.display = 'none';
        document.getElementById('logoutBtn').style.display = 'none';
        document.getElementById('authEmail').value = '';
        document.getElementById('authPassword').value = '';
        document.getElementById('authMessage').innerText = '';
    });
});

// 5. 조회 버튼 로직
document.getElementById('scanBtn').addEventListener('click', async () => {
    const email = document.getElementById('emailInput').value.trim();
    const resultBox = document.getElementById('result-box');
    if (!email) { resultBox.innerHTML = "도메인을 입력해주세요."; return; }

    resultBox.innerHTML = "위협 정보를 가져오는 중";
    try {
        const response = await fetch(`http://127.0.0.1:8000/api/alerts/${email}`);
        const data = await response.json();

        if (data.alerts && data.alerts.length > 0) {
            let htmlContent = `<strong>[${data.email}]</strong><br>총 ${data.alerts.length}건의 위협이 발견되었습니다.<hr style="border: 0; border-top: 1px solid rgba(78, 10, 11, 0.1); margin: 8px 0;">`;
            data.alerts.forEach(alert => {
                htmlContent += `
                    <div class="threat-item">
                        <span class="${alert.threat_level}">[${alert.threat_level}]</span> <strong>출처: ${alert.source}</strong><br>
                        <span style="color: #666; font-size: 12px;">${alert.description}</span>
                    </div>`;
            });
            resultBox.innerHTML = htmlContent;
        } else {
            resultBox.innerHTML = "안전합니다^^ 발견된 위협이 없습니다.";
        }
    } catch (error) {
        resultBox.innerHTML = "<span style='color: #E38792;'>서버 연결 실패</span>";
    }
});

// 6. 대시보드 버튼 로직
document.getElementById('dashboardBtn').addEventListener('click', () => {
    const email = document.getElementById('emailInput').value.trim();
    let targetUrl = 'dashboard.html';
    if (email) targetUrl += `?target=${encodeURIComponent(email)}`;
    chrome.tabs.create({ url: targetUrl });
});