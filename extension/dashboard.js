window.onload = () => {
    const urlParams = new URLSearchParams(window.location.search);
    const targetEmail = urlParams.get('target');
    
    if (targetEmail) {
        document.getElementById('targetInput').value = targetEmail;
        document.getElementById('analyzeBtn').click();
    }
};

document.getElementById('analyzeBtn').addEventListener('click', async () => {
    const target = document.getElementById('targetInput').value.trim();
    if (!target) return alert("모니터링을 원하는 이메일또는 도메인을 입력해주세요");

    document.getElementById('dashboard-content').style.display = 'none';
    document.getElementById('loading').style.display = 'block';

    try {
        const response = await fetch(`http://127.0.0.1:8000/api/alerts/${target}`);
        const data = await response.json();

        document.getElementById('loading').style.display = 'none';
        document.getElementById('dashboard-content').style.display = 'block';

        const tbody = document.getElementById('resultBody');
        tbody.innerHTML = '';

        if (data.alerts && data.alerts.length > 0) {
            document.getElementById('totalCount').innerText = data.alerts.length;
            
            // 종합 위험 점수 계산 (최대 위험도 기준)
            let maxScore = 0;
            data.alerts.forEach(a => {
                if (a.threat_level === 'CRITICAL') maxScore = Math.max(maxScore, 100);
                else if (a.threat_level === 'HIGH') maxScore = Math.max(maxScore, 80);
                else if (a.threat_level === 'MEDIUM') maxScore = Math.max(maxScore, 50);
                else if (a.threat_level === 'LOW') maxScore = Math.max(maxScore, 20);
            });

            const scoreElement = document.getElementById('riskScore');
            const scoreCard = document.getElementById('scoreCard');
            const statusElement = document.getElementById('statusText');

            scoreElement.innerText = maxScore + "점";

            if (maxScore >= 80) {
                scoreElement.style.color = "#4E0A0B"; // CRITICAL 
                scoreCard.style.borderTopColor = "#4E0A0B";
                statusElement.innerText = "심각한 위협";
                statusElement.style.color = "#4E0A0B";
            } else if (maxScore >= 50) {
                scoreElement.style.color = "#E38792"; // MEDIUM
                scoreCard.style.borderTopColor = "#E38792";
                statusElement.innerText = "경고 (확인 요망)";
                statusElement.style.color = "#E38792";
            } else {
                scoreElement.style.color = "#d4a373"; // LOW 
                scoreCard.style.borderTopColor = "#d4a373";
                statusElement.innerText = "주의 (잠재적 위협)";
                statusElement.style.color = "#d4a373";
            }

            data.alerts.forEach(alert => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><span class="${alert.threat_level}">${alert.threat_level}</span></td>
                    <td style="font-weight: bold;">${alert.source}</td>
                    <td style="color: #666;">${alert.description}</td>
                `;
                tbody.appendChild(tr);
            });
        } else {
            // 안전일 때
            document.getElementById('totalCount').innerText = '0';
            
            document.getElementById('riskScore').innerText = '0점';
            document.getElementById('riskScore').style.color = "#9DAD71";
            document.getElementById('scoreCard').style.borderTopColor = "#9DAD71";
            
            document.getElementById('statusText').innerText = "안전함 (Clean)";
            document.getElementById('statusText').style.color = "#9DAD71";
            
            tbody.innerHTML = `<tr><td colspan="3" style="text-align:center; padding: 30px;">발견된 유출 내역이 없습니다. 안전해요</td></tr>`;
        }

    } catch (error) {
        document.getElementById('loading').innerHTML = "<span style='color: #4E0A0B;'>서버 연결 실패 -> 파이썬 백엔드 확인</span>";
    }
});