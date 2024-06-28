# Login Server
- Redis DB에 인증 키를 저장하여 InGame Server (ex. Chatting Server, Game Server 등)에서 해당 인증 키를 확인하여 로그인 유효성을 판단합니다.
-> 동기/비동기 방식 모두 구현
- MySQL DB에 접근하여 계정 정보를 조회 합니다.

- LoginServer
Multi Thread로 작업 처리를 합니다.

- LoginServer_Single
Single Thread로 작업 처리를 합니다.
