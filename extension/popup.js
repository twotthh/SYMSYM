document.getElementById('scanBtn').addEventListener('click', async () => {
    const email = document.getElementById('emailInput').value.trim();
    const resultBox = document.getElementById('result-box');

    if (!email) {
        resultBox.innerHTML = "도메인을 입력해주세요.";
        return;
    }

    resultBox.innerHTML = "위협 정보를 가져오는 중";

    try {
        // 백엔드 FastAPI 서버로 데이터 요청
        const response = await fetch(`http://127.0.0.1:8000/api/alerts/${email}`);
        const data = await response.json();

        if (data.alerts && data.alerts.length > 0) {
            let htmlContent = `<strong>[${data.email}]</strong><br>총 ${data.alerts.length}건의 위협이 발견되었습니다.<hr style="border: 0; border-top: 1px solid #eee; margin: 8px 0;">`;

            data.alerts.forEach(alert => {
                const levelClass = alert.threat_level; 
                htmlContent += `
                    <div class="threat-item">
                        <span class="${levelClass}">[${alert.threat_level}]</span> <strong>출처: ${alert.source}</strong><br>
                        <span style="color: #666; font-size: 12px;">${alert.description}</span>
                    </div>
                `;
            });
            resultBox.innerHTML = htmlContent;
        } else {
            resultBox.innerHTML = "안전합니다! 발견된 위협이 없습니다.";
        }
    } catch (error) {
        resultBox.innerHTML = "<span style='color: #d32f2f;'>서버 연결 실패. 백엔드 서버를 확인해주세요.</span>";
        console.error("통신 에러:", error);
    }
});