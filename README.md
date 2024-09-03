# Login Server
- MySQL DB에 접근하여 계정 정보를 조회
- Redis DB에 인증 키를 저장하여 InGame Server (ex. Chatting Server, Game Server 등)에서 해당 인증 키를 확인하여 로그인 유효성을 판단
-> 메인 업데이트 스레드와 별도로 스레드를 분리하여 비동기 방식으로 DB, Redis 작업 처리

# LoginServer
Multi Thread로 작업 처리

# LoginServer_Single
Single Thread로 작업 처리
