SELECT COUNT(user_id) AS ammount_of_users FROM users;

SELECT COUNT(user_id) AS non_students FROM roles_assigned WHERE role_id != 1;

SELECT password 
FROM passwords p
INNER JOIN roles_assigned r ON p.user_id=r.user_id
WHERE role_id=8;

SELECT COUNT(DISTINCT course_id) FROM term_courses WHERE term_id=2;

SELECT COUNT(enrollment_id) FROM enrollments e
INNER JOIN term_courses t ON e.term_crs_id=t.term_crs_id
INNER JOIN courses c ON c.course_id=t.course_id
WHERE c.title LIKE "ISSC%" AND t.term_id=2;