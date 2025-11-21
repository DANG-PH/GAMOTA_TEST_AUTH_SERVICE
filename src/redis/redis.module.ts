import { Module, Global } from '@nestjs/common';
import { CacheModule } from '@nestjs/cache-manager';
import { redisStore } from 'cache-manager-ioredis-yet';
import KeyvRedis from '@keyv/redis';
import { Keyv } from 'keyv';
import { CacheableMemory } from 'cacheable';


@Global()
@Module({
  imports: [
    CacheModule.registerAsync({
      useFactory: async () => {
        return {
          stores: [
            new Keyv({
              store: new CacheableMemory({ ttl: 0, lruSize: 5000 }),
            }),
            new KeyvRedis(process.env.REDIS_URL), // Kết nối cổng Redis Docker ( Local cổng 6379 )
          ],
          ttl: 0,
          namespace: "gamota"
        };
      },
    }),
  ],
  exports: [CacheModule],
})
export class RedisModule {}