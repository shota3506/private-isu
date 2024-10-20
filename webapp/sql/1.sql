USE `isuconp`;

ALTER TABLE `posts` ADD INDEX idx_posts_created_at (created_at DESC);
ALTER TABLE `posts` ADD INDEX idx_posts_user_id_created_at (user_id, created_at DESC);
ALTER TABLE `comments` ADD INDEX idx_comments_post_id (post_id, created_at DESC);
ALTER TABLE `comments` ADD INDEX idx_comments_user_id (user_id);
