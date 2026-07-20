// 1. 익스텐션이 켜지면 '1분 주기' 알람 등록 
chrome.runtime.onInstalled.addListener(() => {
    chrome.alarms.create("symsymMonitor", { periodInMinutes: 1440 });
    console.log("SYMSYM 백그라운드 상시 감시망 가동 완료 (1분 주기)");
});

// 2. 알람이 울릴 때마다 백그라운드 스캔 실행
chrome.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name === "symsymMonitor") {
        
        // 사용자가 마지막으로 검색했던 타겟(이메일/도메인)과 이전 위협 개수 가져오기
        chrome.storage.local.get(['lastSearchedTarget', 'lastAlertCount'], async (data) => {
            const target = data.lastSearchedTarget;
            if (!target) return; // 등록된 타겟이 없으면 조용히 종료

            console.log(`[백그라운드] '${target}' 상시 모니터링 중...`);

            try {
                // 백엔드 API
                const response = await fetch(`http://43.200.5.232:8000/api/alerts/${target}`);
                const result = await response.json();

                if (result.alerts && result.alerts.length > 0) {
                    const currentCount = result.alerts.length;
                    const prevCount = data.lastAlertCount || 0;

                    // 새로운 위협이 추가로 발견된 경우에만 알림 띄우기
                    if (currentCount > prevCount) {
                        const newAlerts = currentCount - prevCount;
                        
                        // 1. OS 네이티브 푸시 알림 띄우기
                        chrome.notifications.create({
                            type: "basic",
                            iconUrl: "icon.png", // 익스텐션 폴더에 있는 아이콘 파일명으로 맞춰주세요!
                            title: "SYMSYM 긴급 보안 알림",
                            message: `[${target}]\n새로운 보안 위협 ${newAlerts}건이 추가 탐지되었습니다!\n대시보드에서 즉시 확인하세요.`
                        });

                        // 2. 익스텐션 아이콘에 빨간색 뱃지 달아주기
                        chrome.action.setBadgeBackgroundColor({ color: "#E38792" });
                        chrome.action.setBadgeText({ text: currentCount.toString() });

                        // 3. 최신 위협 개수 갱신 (다음 알람 때 비교하기 위해)
                        chrome.storage.local.set({ lastAlertCount: currentCount });
                    }
                }
            } catch (error) {
                console.error("[백그라운드] 서버 연결 실패:", error);
            }
        });
    }
});