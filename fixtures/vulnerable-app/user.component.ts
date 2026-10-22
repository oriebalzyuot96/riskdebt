import { DomSanitizer } from '@angular/platform-browser';

export class UserComponent {
  constructor(private s: DomSanitizer) {}
  render(input: string) {
    return this.s.bypassSecurityTrustHtml(input);
  }
}
