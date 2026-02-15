package restapi

import "github.com/gofiber/fiber/v2"

// jwtError is a custom JWT error handler used by the gofiber/contrib/jwt
// middleware. It returns HTTP 401 with a JSON body describing whether the
// token is missing/malformed or invalid/expired. Without this handler the
// default Fiber JWT middleware returns HTTP 400 for missing tokens.
func jwtError(c *fiber.Ctx, err error) error {
	if err.Error() == "Missing or malformed JWT" {
		return c.Status(fiber.StatusUnauthorized).
			JSON(fiber.Map{"status": "error", "message": "Missing or malformed JWT", "data": nil})
	}
	return c.Status(fiber.StatusUnauthorized).
		JSON(fiber.Map{"status": "error", "message": "Invalid or expired JWT", "data": nil})
}
