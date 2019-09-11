use r2d2_redis_cluster::RedisClusterConnectionManager;

use crate::config;

pub fn get_db_pool(
    database: &config::Database,
) -> diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>> {
    use diesel::pg::PgConnection;
    use diesel::r2d2::{ConnectionManager, Pool};

    let manager = ConnectionManager::<PgConnection>::new(format!(
        "postgres://{}:{}@{}:{}/{}",
        database.username, database.password, database.host, database.port, database.name,
    ));

    let db_pool = Pool::builder()
        .max_size(database.connection_pool_size)
        .build(manager)
        .expect("Unable to create DB connection pool");

    let conn = db_pool.get();
    assert!(conn.is_ok());

    db_pool
}

pub fn get_redis_pool(
    redis: &config::Redis,
    readonly: bool,
) -> r2d2_redis_cluster::r2d2::Pool<RedisClusterConnectionManager> {
    use r2d2_redis_cluster::redis_cluster_rs::redis::IntoConnectionInfo;
    let mut manager = RedisClusterConnectionManager::new(
        vec![format!("redis://{}", redis.address)]
            .iter()
            .map(|c| c.into_connection_info().unwrap())
            .collect(),
    )
    .unwrap();
    manager.set_readonly(readonly);
    let pool = r2d2_redis_cluster::r2d2::Pool::builder()
        .build(manager)
        .expect("Unable to create redis connection pool");

    let conn = pool.get();
    assert!(conn.is_ok());

    pool
}
