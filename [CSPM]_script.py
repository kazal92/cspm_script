import requests
import urllib3
import json
from docxtpl import DocxTemplate
from googletrans import Translator
from dotenv import load_dotenv
import os
from datetime import datetime, timezone, timedelta
load_dotenv()

# SSL 인증서 검증 비활성화 시 발생하는 InsecureRequestWarning 경고를 숨깁니다.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- [설정 및 상수] API 엔드포인트 및 파일 경로 정의 ---
PRISMA_BASE_URL = "https://api.sg.prismacloud.io"
END_POINT_ALERT = "alert"             # 알람 목록 엔드포인트
END_POINT_POLICY = "alert/v1/policy"  # 정책 상세 정보 엔드포인트
# 스크립트 파일이 있는 디렉토리를 기준으로 템플릿 파일 경로 설정
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_PATH = os.path.join(BASE_DIR, "[CSPM]_Template.docx") # 워드 보고서 양식 파일
# PROXIES = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
PROXIES = None

TRANSLATOR = Translator()

def get_timestamp_ms(date_str):
    fmt = "%Y-%m-%d %I:%M %p" # 
    # 문자열 형태의 날짜를 Python datetime 객체로 변환
    dt_naive = datetime.strptime(date_str, fmt)
    # 한국 시간대(KST, UTC+9) 적용
    KST = timezone(timedelta(hours=9))
    dt_kst = dt_naive.replace(tzinfo=KST)
    # Prisma API가 요구하는 Unix Milliseconds 타임스탬프로 변환
    timestamp_ms = int(dt_kst.timestamp() * 1000)

    return timestamp_ms

# [시간 설정] 보고서 대상 기간 설정 (기본값: 오늘 오전 8시 ~ 어제 오전 8시)
now = datetime.now()
# 실행 시점의 날짜에서 시간만 오전 8시로 고정
base_time = now.replace(hour=8, minute=0, second=0, microsecond=0)
start_2 = (base_time - timedelta(days=1)).strftime("%Y-%m-%d %I:%M %p")
end_2 = base_time.strftime("%Y-%m-%d %I:%M %p")

# 특정 날짜로 고정하고 싶을 때 주석 해제 후 사용
# start_2 = "2026-02-11 08:00 AM"
# end_2 = "2026-02-12 08:00 AM"

##################################################################################################################
start = get_timestamp_ms(start_2)
end = get_timestamp_ms(end_2)
# Prisma API 요청 시 사용할 필터 조건 (Open 상태의 알람만 추출)
payload_filters = {
        "filters": [
            {"name": "alert.status", "operator": "=", "value": "open"},
            {"name": "alertRule.name", "operator": "=", "value": "Prisma Default Alert Rule"},
            {"name": "timeRange.type", "operator": "=", "value": "ALERT_STATUS_UPDATED"}
        ],
        "timeRange": {
            "type": "absolute",
            "value": {
                "startTime": start,
                "endTime": end
            }
        },
        "sortBy": ["severity:desc", "alertCount:desc"],
        "size": 100,
        "nextPageToken": "",
        "searchText": "",
        "detailed": True
    }
##################################################################################################################
print(f"[*] 시작 시간: {start_2} ({start})")
print(f"[*] 종료 시간: {end_2} ({end})")

# 결과 저장 경로 설정 (스크립트 경로/result/YYYY-MM-DD)
today_str = datetime.now().strftime('%Y-%m-%d')
output_dir = os.path.join(BASE_DIR, "result", today_str)
os.makedirs(output_dir, exist_ok=True)

# 결과 파일명에 사용할 타임스탬프 (예: 20260203 083000)
timestamp = datetime.now().strftime('%Y%m%d %H%M%S')
original_json_file = os.path.join(output_dir, f"{timestamp}_original.json") # 원본 json 파일명
policy_json_file = os.path.join(output_dir, f"{timestamp}_policy.json") # 정책 메타데이터 json 파일명
processed_json_file = os.path.join(output_dir, f"{timestamp}_processed.json") # 가공 후 json 파일명
out_path = os.path.join(output_dir, f"{timestamp}_ㅁㅁㅁ_클라우드 보안점검 일일 결과보고서.docx") # 최종 보고서 파일명
##################################################################################################################

# 번역 함수 텍스트 번역
def translate_text(text, target_lang='ko'):
    if not text or text == "-":
        return text
    # 언더바(_)를 공백으로 변환하여 번역기 인식률을 높입니다.
    clean_text = text.replace('_', ' ')
    try:
        result = TRANSLATOR.translate(clean_text, dest=target_lang)
        return result.text
    except Exception as e:
        print(f"번역 에러: {e}")
        return clean_text # 에러 시 원문 반환

def get_auth_token():
    """Prisma Cloud API 사용을 위한 JWT 인증 토큰을 발급받습니다."""
    url = "https://api.sg.prismacloud.io/login"
    # url = "http://192.168.0.15:8888"

    payload = {
        "username": os.getenv("PRISMA_ID"),
        "password": os.getenv("PRISMA_PASSWORD")
    }
    headers = {
        'Content-Type': 'application/json; charset=UTF-8',
        'Accept': 'application/json; charset=UTF-8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'
    }
    response = requests.post(url, headers=headers, json=payload, proxies=PROXIES, verify=False)
    print(f"[*] Token 응답 상태 코드: {response.status_code}")

    if response.status_code == 200:
        return response.json().get("token")
    return None

def fetch_prisma_data():
    """Prisma API를 호출하여 정책 정보와 알람 데이터를 수집합니다."""
    token = get_auth_token()
    if not token: return None, None

    headers = {
        'Accept': '*/*',
        'Content-Type': 'application/json; charset=UTF-8',
        'x-redlock-auth': token,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'
    }

    # 1. 정책 정보(findingTypes 등) 가져오기
    policy_finding_map = {}
    try:
        p_res = requests.post(f"{PRISMA_BASE_URL}/{END_POINT_POLICY}", headers=headers, json=payload_filters, proxies=PROXIES, verify=False)
        if p_res.status_code == 200:
            p_data = p_res.json()
            # with open(policy_json_file, 'w', encoding='utf-8') as f: json.dump(p_data, f, indent=4) # 파일생성
            
            # API 응답 구조가 딕셔너리인지 리스트인지 확인하여 처리
            policies = p_data.get('policies', []) if isinstance(p_data, dict) else p_data
            for p in policies:
                if isinstance(p, dict) and p.get('policyId'):
                    policy_finding_map[p['policyId']] = p.get('findingTypes', [])
    except Exception as e:
        print(f"[-] 정책 로드 실패: {e}")

    # 2. 실제 발생한 알람 데이터 가져오기
    try:
        response = requests.post(f"{PRISMA_BASE_URL}/{END_POINT_ALERT}", headers=headers, json=payload_filters, proxies=PROXIES, verify=False)
        print(f"[*] 알람 데이터 상태 코드: {response.status_code}")
        response.raise_for_status()
        raw_json = response.json()
        if isinstance(raw_json, dict): raw_json = raw_json.get('items', [])
        
        # 디버깅 및 기록을 위해 원본 데이터 저장
        with open(original_json_file, 'w', encoding='utf-8') as f: json.dump(raw_json, f, indent=4)
        return raw_json, policy_finding_map
    except Exception as e:
        print(f"[-] 알람 로드 실패: {e}")
        return None, None

def process_alert_data(raw_json, policy_finding_map):
    """수집된 데이터를 심각도별로 분류하고, 주요 필드를 한국어로 번역합니다."""
    # API에서 받아온 순서(desc)를 그대로 유지하기 위해 리스트와 인덱스 맵을 사용합니다.
    policies_in_order = []
    policy_id_to_idx = {}

    alert_groups = {
        'meta': {
            'startTime': start_2,
            'endTime': end_2,
            'startTime_unix': start,
            'endTime_unix': end
        }
    }

    print("[*] 보고서 생성중... 잠시만 기다려주세요 ...")
    for index, item in enumerate(raw_json):
        #  시간 포맷팅 (밀리초 -> 읽기 쉬운 날짜)
        dt = datetime.fromtimestamp(item['alertTime'] / 1000.0)
        item['alertTime_format'] = dt.strftime('%Y-%m-%d %H:%M:%S')

        #  텍스트 병합 및 주요 텍스트 번역 
        p_id = item.get('policyId')
        finding_types = policy_finding_map.get(p_id, [])
        item['policy']['findingTypes'] = ", ".join([ft.lower() for ft in finding_types]) if finding_types else "-"
        translated_types = [translate_text(ft) for ft in finding_types]
        item['policy']['findingTypes_ko'] = ", ".join(translated_types) if translated_types else "-"

        item['policy']['name_ko'] = translate_text(item['policy']['name'])
        item['policy']['description_ko'] = translate_text(item['policy'].get('description', ''))
        item['policy']['recommendation_ko'] = translate_text(item['policy'].get('recommendation', ''))

        # 리전 정보가 없는 경우 처리
        if not item['resource'].get('regionId'): item['resource']['regionId'] = "-"

        # 4. 심각도 분류 및 그룹화
        sev = item['policy'].get('severity', '').lower()
        if sev == 'informational': sev = 'info' # 명칭 통일
        item['policy']['severity'] = sev
        
        if p_id not in policy_id_to_idx:
            policy_id_to_idx[p_id] = len(policies_in_order)
            policies_in_order.append({
                'policy': item['policy'],
                'severity': sev,
                'resources': [],
                'count': 0,
                'cloudType': item['resource'].get('cloudType', 'N/A'),
                'account_tags': set()  # 계정 태그를 저장
            })
        
        target_policy = policies_in_order[policy_id_to_idx[p_id]]
        target_policy['resources'].append(item)
        target_policy['count'] += 1

        # 계정 분류 로직 (dw 포함 -> DW, dev 포함 -> DEV, 그 외 -> PRD)
        acc_name = item.get('resource', {}).get('account', '').lower()
        if 'dw' in acc_name:
            target_policy['account_tags'].add("DW")
        elif 'dev' in acc_name:
            target_policy['account_tags'].add("DEV")
        else:
            target_policy['account_tags'].add("PRD")

    # 모든 처리가 끝난 후 set을 문자열로 변환하고 정리
    for p in policies_in_order:
        p['account_tags'] = "\n".join(sorted(p['account_tags']))

    alert_groups['policies'] = policies_in_order

    with open(processed_json_file, 'w', encoding='utf-8') as f:
        json.dump(alert_groups, f, indent=4, ensure_ascii=False)
    return alert_groups

def data_request():
    """데이터 수집과 가공을 순차적으로 실행합니다."""
    raw_data, policy_map = fetch_prisma_data()
    if not raw_data: return None
    return process_alert_data(raw_data, policy_map)

def wordCreate(alert_groups):
    """가공된 데이터를 워드 템플릿에 주입하여 최종 보고서를 생성합니다."""
    doc = DocxTemplate(TEMPLATE_PATH)
    
    all_policies = alert_groups.get('policies', [])
    
    # 전체 리스트에 순번(index) 부여 (API에서 온 순서 그대로)
    for i, p in enumerate(all_policies, 1):
        p['index'] = i

    # 심각도별 필터링 (이미 API에서 정렬되어 왔으므로 순서가 유지됨)
    alerts_critical = [p for p in all_policies if p['severity'] == 'critical']
    alerts_high = [p for p in all_policies if p['severity'] == 'high']
    alerts_medium = [p for p in all_policies if p['severity'] == 'medium']
    alerts_low = [p for p in all_policies if p['severity'] == 'low']
    alerts_info = [p for p in all_policies if p['severity'] == 'info']
    
    # 워드 템플릿의 {{ 변수명 }} 자리에 들어갈 데이터 매핑
    context = {
        'alerts': all_policies,
        'alerts_critical': alerts_critical,
        'alerts_high': alerts_high,
        'alerts_medium': alerts_medium,
        'alerts_low': alerts_low,
        'alerts_info': alerts_info,
        'alerts_meta': alert_groups['meta'],

        'critical_count': sum(p['count'] for p in alerts_critical),
        'high_count': sum(p['count'] for p in alerts_high),
        'medium_count': sum(p['count'] for p in alerts_medium),
        'low_count': sum(p['count'] for p in alerts_low),
        'info_count': sum(p['count'] for p in alerts_info),
        'today': datetime.now().strftime('%Y.%m.%d')
    }

    doc.render(context) # 데이터 주입
    doc.save(out_path)  # 파일 저장
    print(f"[+] 보고서 생성 완료: {out_path}")

if __name__ == '__main__':
    # 프로그램 시작점
    alert_data_groups = data_request()
    if alert_data_groups:
        wordCreate(alert_data_groups)
    else:
        print("[-] 처리할 데이터가 없습니다.")