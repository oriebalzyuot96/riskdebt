export class AuthService {
  save(res: any) {
    sessionStorage.setItem('access_token', res.token);
    document.cookie = 'jwt=' + res.token;
    console.log('login ok', res.token);
    return fetch('/api/me?token=' + res.token);
  }
}
