export const verifyAccountTemplate = (
  username: string,
  otp: string
) => `
<!DOCTYPE html>
<html>
<body>
  <h2>Hello ${username}</h2>

  <p>Your verification code:</p>

  <div
    style="
      font-size:32px;
      font-weight:bold;
      letter-spacing:6px;
      padding:20px;
      background:#f5f5f5;
      display:inline-block;
    "
  >
    ${otp}
  </div>

  <p>
    This code expires in 10 minutes.
  </p>
</body>
</html>
`;