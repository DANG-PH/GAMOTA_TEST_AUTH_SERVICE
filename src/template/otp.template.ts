export function otpEmailTemplate(user: any, otp: string) {
  return `
        <meta name="color-scheme" content="light dark">
        <meta name="supported-color-schemes" content="light dark">

        <div style="
          font-family: Arial, sans-serif;
          background: #0f172a !important;
          color: #f8fafc !important;
          padding: 20px;
          border-radius: 12px;
          max-width: 450px;
          margin: auto;
          border: 2px solid #38bdf8 !important;
        ">
          <div style="text-align: center; margin-bottom: 12px;">
            <img src="https://vcdn1-vnexpress.vnecdn.net/2025/03/20/GameMota-1742437039-1742437044.png?w=1200&h=0&q=100&dpr=1&fit=crop&s=kMyUCXVG9CE_B4dSdBIU6w"
              alt="GAMOTA Logo"
              style="
                width: 120px;
                height: 120px;
                object-fit: cover;
                border-radius: 50%;
                border: 2px solid #38bdf8;
                box-shadow: 0 0 10px rgba(56, 189, 248, 0.3);
              " />
          </div>

          <h2 style="text-align:center; margin-bottom: 12px; color: #38bdf8 !important;">
            GAMOTA TEST
          </h2>

          <p style="font-size:14px; line-height:1.5; color: #f8fafc !important;">
            Xin chào ${user.realname},<br/>
            Bạn đang yêu cầu đăng nhập tài khoản. Vui lòng dùng mã bên dưới để xác thực:
          </p>

          <div style="
            margin: 20px auto;
            padding: 12px 0;
            background: #1e293b !important;
            border-radius: 10px;
            text-align:center;
            border: 1px solid #38bdf8 !important;
          ">
            <span style="
              font-size: 28px;
              font-weight: bold;
              color: #38bdf8 !important;
              font-family: 'Courier New', monospace;
            ">
              ${otp}
            </span>
          </div>

          <p style="font-size:14px; color: #f8fafc !important;">
            Mã OTP có hiệu lực trong <b>5 phút</b>.<br/>
            Không cung cấp mã cho bất kỳ ai để tránh mất tài khoản.
          </p>

          <hr style="border: none; border-top: 1px solid #334155; margin: 20px 0;" />

          <div style="text-align:center; font-size:12px; color:#94a3b8 !important;">
            © GAMOTA – 2025 <br/>
          </div>
        </div>
        `;
}


export function securityAlertEmailTemplate(realname: string) {
  return `
    <meta name="color-scheme" content="light dark">
    <meta name="supported-color-schemes" content="light dark">

    <div style="
      font-family: Arial, sans-serif;
      background: #2d1b1b !important;
      color: #fff1f2 !important;
      padding: 20px;
      border-radius: 12px;
      max-width: 450px;
      margin: auto;
      border: 2px solid #fb7185 !important;
    ">
      <div style="text-align: center; margin-bottom: 12px;">
        <img src="https://vcdn1-vnexpress.vnecdn.net/2025/03/20/GameMota-1742437039-1742437044.png?w=1200&h=0&q=100&dpr=1&fit=crop&s=kMyUCXVG9CE_B4dSdBIU6w"
          alt="GAMOTA LOGO"
          style="
            width: 120px;
            height: 120px;
            object-fit: cover;
            border-radius: 50%;
            border: 2px solid #fb7185;
            box-shadow: 0 0 12px rgba(251, 113, 133, 0.4);
          " />
      </div>

      <h2 style="text-align:center; margin-bottom: 12px; color: #fb7185 !important;">
        CẢNH BÁO BẢO MẬT – GAMOTA TEST
      </h2>

      <p style="font-size:14px; line-height:1.5; color: #ffe4e6 !important;">
        Xin chào <b>${realname}</b>,<br/>
        Chúng tôi vừa phát hiện nhiều lần đăng nhập thất bại bất thường
        vào tài khoản của bạn trong thời gian ngắn.
      </p>

      <div style="
        background: #3f1d1d !important;
        padding: 14px;
        border-radius: 10px;
        border: 1px solid #fb7185 !important;
        margin: 18px 0;
        text-align:center;
        color:#fecdd3 !important;
      ">
        Tài khoản của bạn đã bị <b>khóa tạm thời 10 phút</b><br/>
        để đảm bảo an toàn.
      </div>

      <p style="font-size:14px; color: #ffe4e6 !important;">
        Nếu đây là bạn, vui lòng thử lại sau.<br/>
        Nếu không phải bạn, hãy đổi mật khẩu ngay khi đăng nhập lại được.
      </p>

      <hr style="border: none; border-top: 1px solid #7f1d1d; margin: 20px 0;" />

      <div style="text-align:center; font-size:12px; color:#fecdd3 !important;">
        © GAMOTA – 2025 <br/>
      </div>
    </div>
  `;
}