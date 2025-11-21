import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuthEntity } from './auth.entity';
import * as bcrypt from 'bcrypt';
import type { LoginRequest,LoginResponse, RegisterResponse, RegisterRequest, VerifyOtpRequest, VerifyOtpResponse } from 'proto/auth.pb';
import { JwtService } from '@nestjs/jwt';
import { MailerService } from '@nestjs-modules/mailer';
import { Inject } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from '@nestjs/cache-manager';
import { otpEmailTemplate } from 'src/template/otp.template';
import {securityAlertEmailTemplate} from 'src/template/otp.template';
import { RpcException } from '@nestjs/microservices';
import { status } from '@grpc/grpc-js';
import { ClientProxy } from '@nestjs/microservices';
import * as crypto from 'crypto';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(AuthEntity)
    private readonly userRepository: Repository<AuthEntity>,
    private jwtService: JwtService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    @Inject('EMAIL_SERVICE') private readonly emailClient: ClientProxy,
  ) {}

  async saveUser(user: AuthEntity): Promise<AuthEntity> {
    return await this.userRepository.save(user);
  }

  async getAllUsers(): Promise<AuthEntity[]> {
    return await this.userRepository.find();
  }

  async existsByUsername(username: string): Promise<boolean> {
    const count = await this.userRepository.count({ where: { username } });
    return count > 0;
  }

  async findByUsername(username: string): Promise<AuthEntity | null> {
    return await this.userRepository.findOne({ where: { username } });
  }

  async register(data: RegisterRequest): Promise<RegisterResponse> {
    const exists = await this.existsByUsername(data.username);
    if (exists)  throw new RpcException({code: status.UNAUTHENTICATED ,message: 'Đã tồn tại User'});

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(data.password, salt);

    const userMoi = new AuthEntity();
    userMoi.username = data.username;
    userMoi.password = passwordHash;
    userMoi.email = data.email;
    userMoi.realname = data.realname;
    userMoi.role = 'USER';

    await this.saveUser(userMoi);

    return { success: true, auth_id: userMoi.id };
  }

  async login(data: LoginRequest): Promise<LoginResponse> {
    const user = await this.findByUsername(data.username);
    if (!user) throw new RpcException({code: status.UNAUTHENTICATED ,message: 'User not found'});

    const isLocked = await this.cacheManager.get(`LOCK:${data.username}`);
    if (isLocked) throw new RpcException({code: status.PERMISSION_DENIED , message: 'Account temporarily locked. Try again later.'});

    const passwordMatch = await bcrypt.compare(data.password, user.password);
    if (!passwordMatch) {
      const attempts = await this.incrementLoginAttempt(data.username);

      if (attempts > 5) {
        await this.cacheManager.set(`LOCK:${user.username}`, true, 10 * 60 * 1000);
        this.emailClient.emit('send_email', {
          to: user.email,
          subject: 'Cảnh báo bảo mật – Tài khoản bị khóa tạm thời',
          html: securityAlertEmailTemplate(user.realname),
        }); 
        throw new RpcException({code: status.UNAUTHENTICATED , message: 'Sai mật khẩu quá nhiều. Tài khoản bị vô hiệu 10 phút'});
      }

      throw new RpcException({code: status.UNAUTHENTICATED ,message: 'Sai mật khẩu, vui lòng thử lại'});
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await this.cacheManager.set(`OTP:${user.username}`, otp, 5 * 60 * 1000);

    this.emailClient.emit('send_email', {
      to: user.email,
      subject: 'Xác thực đăng nhập – GAMOTA',
      html: otpEmailTemplate(user, otp),
    });

    const sessionId = Buffer.from(user.username).toString('base64');
    return { sessionId };
  }

  async verifyOtp(data : VerifyOtpRequest): Promise<VerifyOtpResponse> {
    const username = Buffer.from(data.sessionId, 'base64').toString('ascii');
    const user = await this.findByUsername(username);

    if (!user) throw new RpcException({ code: status.UNAUTHENTICATED, message: 'User not found'});
    
    const otpInCache = await this.cacheManager.get<string>(`OTP:${username}`);

    if (!otpInCache || otpInCache !== data.otp) {
      throw new RpcException({ code: status.UNAUTHENTICATED, message: 'OTP sai hoặc hết hạn'});
    }

    // Xóa OTP sau khi sử dụng
    await this.cacheManager.del(`OTP:${username}`);

    const payload = { userId: user.id, username: user.username, role: user.role };

    const accessToken = this.jwtService.sign(payload, { expiresIn: '1d' }); 
    const refreshToken = this.jwtService.sign(
      { username: user.username },
      { expiresIn: '7d' }
    );

    await this.cacheManager.set(
      `REFRESH:${user.username}`,
      refreshToken,
      7 * 24 * 60 * 60 * 1000 // 7 ngày
    );

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      auth_id: user.id,
      role: user.role
    };
  }

  async refresh(refreshToken: string): Promise<{ access_token: string, refresh_token: string }> {
    try {
      const decoded = this.jwtService.verify(refreshToken);

      const username = decoded.username;

      const savedToken = await this.cacheManager.get<string>(`REFRESH:${username}`);

      if (!savedToken || savedToken !== crypto.createHash('sha256').update(refreshToken).digest('hex')) {
        throw new RpcException({
          code: status.UNAUTHENTICATED,
          message: 'Invalid refresh token'
        });
      }

      const user = await this.findByUsername(username);
      if (!user) {
        throw new RpcException({ code: status.UNAUTHENTICATED, message: 'User not allowed' });
      }

      const newAccessToken = this.jwtService.sign(
        { userId: user.id, username: username, role: user.role },
        { expiresIn: '1d' }
      );

      const newRefreshToken = this.jwtService.sign(
        { username: username },
        { expiresIn: '7d' }
      );

      const hashed = crypto.createHash('sha256')
                           .update(newRefreshToken)
                           .digest('hex'); // nếu bỏ digest thì hashed là giá trị binary khó đọc, có thể dùng hex hoặc base64

      const ttl = await this.cacheManager.ttl(`REFRESH:${username}`);

      const timeConLaiTokenCu = (ttl || Date.now() + 7 * 24 * 60 * 60 * 1000) - Date.now();

      await this.cacheManager.set(
        `REFRESH:${username}`,
        hashed,
        timeConLaiTokenCu // 7 * 24 * 60 * 60 * 1000 (Nếu muốn login vô hạn)
      );

      return { 
        access_token: newAccessToken,
        refresh_token: newRefreshToken
      };
    } catch (error) {
      throw new RpcException({
          code: status.UNAUTHENTICATED,
          message: 'Invalid refresh token'
      });
    }
  }

  private async incrementLoginAttempt(username: string): Promise<number> {
    const key = `LOGIN_FAIL:${username}`;
    let attempts = (await this.cacheManager.get<number>(key)) || 0;
    attempts++;
    await this.cacheManager.set(key, attempts, 15 * 60 * 1000); 
    return attempts;
  }
}