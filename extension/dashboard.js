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
    if (!target) return alert("분석할 이메일이나 도메인을 입력해주세요");

    document.getElementById('dashboard-content').style.display = 'none';
    document.getElementById('loading').style.display = 'block';

    try {
        // 파이썬 백엔드 서버로 AWS DB 조회 요청
        const response = await fetch(`http://127.0.0.1:8000/api/alerts/${target}`);
        const data = await response.json();

        document.getElementById('loading').style.display = 'none';
        document.getElementById('dashboard-content').style.display = 'block';

        const tbody = document.getElementById('resultBody');
        tbody.innerHTML = '';

        if (data.alerts && data.alerts.length > 0) {
            document.getElementById('totalCount').innerText = data.alerts.length;
            
            // High/Critical 등급 개수 계산
            const highRiskCount = data.alerts.filter(a => a.threat_level === 'HIGH' || a.threat_level === 'CRITICAL').length;
            document.getElementById('highCount').innerText = highRiskCount;
            
            document.getElementById('statusText').innerText = "위험 감지됨";
            document.getElementById('statusText').style.color = "#E38792";

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
            // 털린 기록이 없을 때
            document.getElementById('totalCount').innerText = '0';
            document.getElementById('highCount').innerText = '0';
            document.getElementById('statusText').innerText = "안전함 (Clean)";
            document.getElementById('statusText').style.color = "#9DAD71";
            tbody.innerHTML = `<tr><td colspan="3" style="text-align:center; padding: 30px;">발견된 유출 내역이 없습니다. 안전해요^^</td></tr>`;
        }

    } catch (error) {
        document.getElementById('loading').innerHTML = "<span style='color: #4E0A0B;'>서버 연결 실패. 파이썬 백엔드를 확인해주세요.</span>";
    }
});