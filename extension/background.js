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
    if (!target) return alert("모니터링할 도메인/이메일/전화번호 을 입력해주세요!");

    const btn = document.getElementById('analyzeBtn');
    btn.classList.add('loading');
    btn.innerHTML = '모니터링 중···';
    
    document.getElementById('liveStatus').innerHTML = `<span class="dot"></span>실시간 모니터링 진행 중...`;

    try {
        const response = await fetch(`http://43.200.5.232:8000/api/alerts/${target}`);
        const data = await response.json();

        const tbody = document.getElementById('resultBody');
        tbody.innerHTML = '';

        if (data.alerts && data.alerts.length > 0) {
            document.getElementById('totalCount').innerText = data.alerts.length;
            document.getElementById('logCountText').innerText = `${data.alerts.length}건 표시 중`;
            
            let maxScore = 0;
            data.alerts.forEach(a => {
                if (a.threat_level === 'CRITICAL') maxScore = Math.max(maxScore, 100);
                else if (a.threat_level === 'HIGH') maxScore = Math.max(maxScore, 80);
                else if (a.threat_level === 'MEDIUM') maxScore = Math.max(maxScore, 50);
                else if (a.threat_level === 'LOW') maxScore = Math.max(maxScore, 20);
            });

            document.getElementById('riskScore').innerText = maxScore;
            
            setTimeout(() => {
                document.getElementById('scoreMeter').style.width = maxScore + '%';
            }, 100);

            const scoreCard = document.getElementById('scoreCard');
            const statusText = document.getElementById('statusText');

            if (maxScore >= 80) {
                scoreCard.style.background = 'var(--coral)';
                statusText.style.color = 'var(--coral)';
                statusText.innerHTML = `심각<small id="statusDesc">즉각적인 조치가 필요합니다.</small>`;
            } else if (maxScore >= 50) {
                scoreCard.style.background = 'var(--amber)';
                statusText.style.color = 'var(--amber)';
                statusText.innerHTML = `경고<small id="statusDesc">확인이 필요한 위협이 있습니다.</small>`;
            } else {
                scoreCard.style.background = 'var(--mint)';
                statusText.style.color = 'var(--mint)';
                statusText.innerHTML = `주의<small id="statusDesc">잠재적 위협이 감지됐어요.</small>`;
            }

            data.alerts.forEach(alert => {
                let tagClass = 'low';
                let displayLevel = alert.threat_level;
                
                if (displayLevel === 'CRITICAL' || displayLevel === 'HIGH') tagClass = 'high';
                else if (displayLevel === 'MEDIUM') tagClass = 'mid';
                else tagClass = 'low';

                // 백엔드에서 받은 risk_reason 배열을 쉼표로 연결
                const riskReasons = alert.risk_reason && alert.risk_reason.length > 0 
                    ? alert.risk_reason.join(', ') 
                    : '추가 탐지 근거 없음';

                // 행과 상세 정보를 모두 감싸는 컨테이너 생성
                const itemDiv = document.createElement('div');
                itemDiv.className = 'alert-item';
                
                // 상세 설명이 길 경우를 대비해 요약문(50자) 생성
                const shortDesc = alert.description.length > 50 
                    ? alert.description.substring(0, 50) + '...' 
                    : alert.description;

                // 클릭 이벤트(toggleAccordion) 추가 및 화살표 아이콘(arrow-icon) 클래스 부여
                itemDiv.innerHTML = `
                    <div class="log-row" onclick="toggleAccordion(this)">
                        <span class="risk-tag ${tagClass}">${displayLevel}</span>
                        <span class="source-tag"><span class="source-dot"></span>${alert.source}</span>
                        <span class="detail-text truncate">${shortDesc}</span>
                        <span class="chev arrow-icon">›</span>
                    </div>
                    <div class="alert-details">
                        <p><strong>탐지 근거 : </strong> ${riskReasons}</p>
                        <p><strong>상세 설명 : </strong> ${alert.description}</p>
                        ${alert.url ? `<p><strong>참고 링크 : </strong> <a href="${alert.url}" target="_blank" style="color: var(--brand); text-decoration: underline;">바로가기</a></p>` : ''}
                    </div>
                `;
                tbody.appendChild(itemDiv);
            });
            
        } else {
            document.getElementById('totalCount').innerText = '0';
            document.getElementById('logCountText').innerText = `0건 표시 중`;
            document.getElementById('riskScore').innerText = '0';
            document.getElementById('scoreMeter').style.width = '0%';
            
            document.getElementById('scoreCard').style.background = 'var(--safe)';
            
            const statusText = document.getElementById('statusText');
            statusText.style.color = 'var(--safe)';
            statusText.innerHTML = `안전<small id="statusDesc">발견된 보안 위협이 없습니다</small>`;
            
            tbody.innerHTML = `
                <div class="log-row" style="grid-template-columns: 1fr; text-align: center; padding: 40px;">
                    <span class="detail-text">외부로 유출된 흔적이 없습니다. 안전합니다!</span>
                </div>
            `;
        }

        const now = new Date();
        const timeString = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-${String(now.getDate()).padStart(2,'0')} ${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}`;
        document.getElementById('lastScanTime').innerText = `마지막 스캔 · ${timeString} KST`;

    } catch (error) {
        document.getElementById('resultBody').innerHTML = `
            <div class="log-row" style="grid-template-columns: 1fr; text-align: center; padding: 40px;">
                <span class="detail-text" style="color: var(--coral);">서버 연결 실패 -> 백엔드 확인</span>
            </div>
        `;
    } finally {
        btn.classList.remove('loading');
        btn.innerHTML = '모니터링 시작';
        document.getElementById('liveStatus').innerHTML = `<span class="dot"></span>실시간 모니터링 대기 중`;
    }
});

window.toggleAccordion = function(element) {
    const details = element.nextElementSibling;
    const arrow = element.querySelector('.arrow-icon');

    // 상세 내용 열기/닫기
    details.classList.toggle('show');
    
    // 화살표 90도 회전
    arrow.classList.toggle('open');
    
    // 열렸을 때 기존 밑줄을 숨겨서 깔끔하게 보이게 처리
    if(details.classList.contains('show')) {
        element.style.borderBottom = 'none';
    } else {
        element.style.borderBottom = '1px solid var(--line)';
    }
};