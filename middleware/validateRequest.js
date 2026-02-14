import { ZodError } from "zod";
import { validationResult } from "express-validator";

/*
  Usage:
  validateRequest({
    body: schema,
    query: schema,
    params: schema
  })
*/

export const validateRequest = (schemasOrReq = {}, res, next) => {
  // Direct middleware mode: validateRequest
  if (res && next) {
    const result = validationResult(schemasOrReq);
    if (!result.isEmpty()) {
      return res.status(400).json({
        message: "Validation failed",
        errors: result.array()
      });
    }
    return next();
  }

  // Factory mode: validateRequest({ body/query/params })
  const schemas = schemasOrReq;
  return async (req, resInner, nextInner) => {
    try {
      if (schemas.body) {
        req.body = schemas.body.parse(req.body);
      }

      if (schemas.query) {
        req.query = schemas.query.parse(req.query);
      }

      if (schemas.params) {
        req.params = schemas.params.parse(req.params);
      }

      return next();

    } catch (error) {
      if (error instanceof ZodError) {
        return resInner.status(400).json({
          message: "Validation failed",
          errors: error.errors.map((err) => ({
            field: err.path.join("."),
            message: err.message
          }))
        });
      }

      return resInner.status(500).json({
        message: "Validation error"
      });
    }
  };
};
