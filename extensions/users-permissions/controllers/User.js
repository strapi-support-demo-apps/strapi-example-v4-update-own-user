const _ = require('lodash');
const { sanitizeEntity } = require('strapi-utils');

const sanitizeUser = user =>
  sanitizeEntity(user, {
    model: strapi.query('user', 'users-permissions').model,
  });

module.exports = {  /**
   * Update authenticated user.
   * @return {Object|Array}
   */
  async updateMe(ctx) {
    const advancedConfigs = await strapi
      .store({
        environment: '',
        type: 'plugin',
        name: 'users-permissions',
        key: 'advanced',
      })
      .get();

    const user = ctx.state.user;
    const { id, email, username, password } = user;

    if (!user) {
      return ctx.badRequest(null, [{ messages: [{ id: 'No authorization header was found' }] }]);
    }

    if (_.has(ctx.request.body, 'email') && !email) {
      return ctx.badRequest('email.notNull');
    }

    if (_.has(ctx.request.body, 'username') && !username) {
      return ctx.badRequest('username.notNull');
    }

    if (_.has(ctx.request.body, 'password') && !password && user.provider === 'local') {
      return ctx.badRequest('password.notNull');
    }

    if (_.has(ctx.request.body, 'role')) {
      return ctx.badRequest(null, [{ messages: [{ id: 'Cannot update own role' }] }]);
    }

    if (_.has(ctx.request.body, 'confirmed')) {
      return ctx.badRequest(null, [{ messages: [{ id: 'Cannot change own confirmed status' }] }]);
    }

    if (_.has(ctx.request.body, 'provider')) {
      return ctx.badRequest(null, [{ messages: [{ id: 'Cannot change own provider' }] }]);
    }

    if (_.has(ctx.request.body, 'resetPasswordToken')) {
      return ctx.badRequest(null, [{ messages: [{ id: 'Cannot set own password reset token' }] }]);
    }

    if (_.has(ctx.request.body, 'blocked')) {
      return ctx.badRequest(null, [{ messages: [{ id: 'Cannot change own blocked status' }] }]);
    }

    if (_.has(ctx.request.body, 'username')) {
      const userWithSameUsername = await strapi
        .query('user', 'users-permissions')
        .findOne({ username });

      if (userWithSameUsername && userWithSameUsername.id != id) {
        return ctx.badRequest(
          null,
          formatError({
            id: 'Auth.form.error.username.taken',
            message: 'username.alreadyTaken.',
            field: ['username'],
          })
        );
      }
    }

    if (_.has(ctx.request.body, 'email') && advancedConfigs.unique_email) {
      const userWithSameEmail = await strapi.query('user', 'users-permissions').findOne({ email });

      if (userWithSameEmail && userWithSameEmail.id != id) {
        return ctx.badRequest(
          null,
          formatError({
            id: 'Auth.form.error.email.taken',
            message: 'Email already taken',
            field: ['email'],
          })
        );
      }
    }

    let updateData = {
      ...ctx.request.body,
    };

    if (_.has(ctx.request.body, 'password') && password === user.password) {
      delete updateData.password;
    }

    const data = await strapi.plugins['users-permissions'].services.user.edit({ id }, updateData);

    const newData = sanitizeUser(data);
    ctx.send(newData);
  },
}
