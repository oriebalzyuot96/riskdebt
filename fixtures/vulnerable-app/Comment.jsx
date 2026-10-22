export function Comment({ html }) {
  localStorage.setItem("authToken", "abc");
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
