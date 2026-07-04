var KIND_OPTIONS = [
  {label: 'Kind 0 - Profile Metadata', value: 0, sensitive: true,
    description: 'Updates your Nostr profile (name, picture, about). Sensitive: changes your public identity.'},
  {label: 'Kind 1 - Short Text Note', value: 1, sensitive: false,
    description: 'A regular Nostr post. Used by CyberHerd Messaging and other extensions to publish notes.'},
  {label: 'Kind 3 - Contact List', value: 3, sensitive: true,
    description: 'Your follow list. Sensitive: replaces your entire contact list.'},
  {label: 'Kind 4 - Encrypted DM (legacy)', value: 4, sensitive: true,
    description: 'NIP-04 encrypted direct message. Sensitive: can send messages as you.'},
  {label: 'Kind 5 - Deletion Request', value: 5, sensitive: true,
    description: 'Request to delete events. Sensitive: removes your published content.'},
  {label: 'Kind 6 - Repost', value: 6, sensitive: false,
    description: 'Repost/boost another user\'s note to your followers.'},
  {label: 'Kind 7 - Reaction', value: 7, sensitive: false,
    description: 'Like or react to another user\'s note.'},
  {label: 'Kind 1311 - Chat Reply', value: 1311, sensitive: false,
    description: 'Reply to a live event (kind 30311). Used by CyberHerd Messaging.'},
  {label: 'Kind 9734 - Zap Request', value: 9734, sensitive: false,
    description: 'NIP-57 zap request. Used by Split Payments to send zaps via LNURL.'},
  {label: 'Kind 9735 - Zap Receipt', value: 9735, sensitive: false,
    description: 'NIP-57 zap receipt. Used by LNURLp to confirm incoming zaps.'},
  {label: 'Kind 10002 - Relay List', value: 10002, sensitive: true,
    description: 'Your preferred relay list. Sensitive: changes where your events are published.'},
  {label: 'Kind 22242 - Client Auth', value: 22242, sensitive: true,
    description: 'NIP-42 relay authentication. Sensitive: authenticates as you to relays.'},
  {label: 'Kind 30311 - Live Event', value: 30311, sensitive: false,
    description: 'Addressable live event (stream, activity). Used by CyberHerd.'}
]

var KIND_MAP = {}
KIND_OPTIONS.forEach(function (k) {
  KIND_MAP[k.value] = k
})

window.app = Vue.createApp({
  el: '#vue',
  mixins: [windowMixin],
  watch: {
    selectedWallet() {
      this.getKeys()
      this.getPermissions()
      this.getLogs()
      this.discoverExtensions()
    }
  },
  data() {
    return {
      selectedWallet: null,
      keys: [],
      permissions: [],
      logs: [],
      discoveredExtensions: [],
      extensionOptions: [],
      newKeyInput: '',
      showPermDialog: false,
      showEditPermDialog: false,
      showEditKeyDialog: false,
      editKeyForm: {
        id: null,
        label: ''
      },
      kindOptions: KIND_OPTIONS,
      permForm: {
        key_id: null,
        extension_id: null,
        kind: null,
        customKind: null,
        rate_limit_count: null,
        rate_limit_seconds: null
      },
      editPermForm: {
        id: null,
        rate_limit_count: null,
        rate_limit_seconds: null
      },
      keyCols: [
        {
          name: 'label',
          label: 'Label',
          field: 'label',
          align: 'left'
        },
        {
          name: 'pubkey_hex',
          label: 'Public Key',
          field: 'pubkey_hex',
          align: 'left'
        },
        {
          name: 'created_at',
          label: 'Created',
          field: 'created_at',
          align: 'left',
          format: val => new Date(val).toLocaleString()
        },
        {name: 'actions', label: 'Actions', align: 'right'}
      ],
      permCols: [
        {
          name: 'extension_id',
          label: 'Extension',
          field: 'extension_id',
          align: 'left'
        },
        {
          name: 'kind',
          label: 'Event Kind',
          field: 'kind',
          align: 'left',
          format: val => {
            var k = KIND_MAP[val]
            return k ? k.label : 'Kind ' + val
          }
        },
        {name: 'rate_limit', label: 'Rate Limit', align: 'left'},
        {
          name: 'created_at',
          label: 'Granted',
          field: 'created_at',
          align: 'left',
          format: val => new Date(val).toLocaleString()
        },
        {name: 'actions', label: 'Actions', align: 'right'}
      ],
      logCols: [
        {
          name: 'created_at',
          label: 'Time',
          field: 'created_at',
          align: 'left',
          format: val => new Date(val).toLocaleString()
        },
        {
          name: 'extension_id',
          label: 'Extension',
          field: 'extension_id',
          align: 'left'
        },
        {
          name: 'kind',
          label: 'Event Kind',
          field: 'kind',
          align: 'left',
          format: val => {
            var k = KIND_MAP[val]
            return k ? k.label : 'Kind ' + val
          }
        },
        {name: 'event_id', label: 'Event ID', align: 'left'}
      ],
      logPagination: {
        sortBy: 'created_at',
        descending: true,
        page: 1,
        rowsPerPage: 20,
        rowsNumber: 0
      }
    }
  },
  computed: {
    keyOptions() {
      return this.keys.map(k => ({
        label: k.label
          ? k.label + ' - ' + this.shortKey(k.pubkey_hex)
          : this.shortKey(k.pubkey_hex),
        value: k.id
      }))
    },
    selectedKindSensitive() {
      if (this.permForm.kind === null) return false
      var k = KIND_MAP[this.permForm.kind]
      return k ? k.sensitive : false
    },
    selectedKindDescription() {
      if (this.permForm.kind === null) return ''
      var k = KIND_MAP[this.permForm.kind]
      return k ? k.description : ''
    },
    selectedExtDescription() {
      if (!this.permForm.extension_id) return ''
      var e = this.extensionOptions.find(
        o => o.value === this.permForm.extension_id
      )
      return e ? e.description : ''
    }
  },
  methods: {
    shortKey(hex) {
      if (!hex) return ''
      return hex.substring(0, 12) + '...' + hex.substring(hex.length - 8)
    },
    copyText(text) {
      navigator.clipboard.writeText(text).then(() => {
        Quasar.Notify.create({message: 'Copied!', timeout: 500})
      })
    },
    extName(extId) {
      var ext = this.discoveredExtensions.find(e => e.extension_id === extId)
      return ext ? ext.extension_name : extId
    },

    // --- Discovery ---
    discoverExtensions() {
      LNbits.api
        .request(
          'GET',
          '/nsecbunker/api/v1/discover',
          this.selectedWallet.adminkey
        )
        .then(response => {
          this.discoveredExtensions = response.data
          this.extensionOptions = response.data.map(ext => ({
            label: ext.extension_name,
            value: ext.extension_id,
            description: ext.requirements.map(r => r.description).join(' ')
          }))
        })
        .catch(err => {
          LNbits.utils.notifyApiError(err)
        })
    },
    quickSetup(extId) {
      if (this.keys.length === 0) return
      var keyId = this.keys[0].id
      LNbits.api
        .request(
          'POST',
          '/nsecbunker/api/v1/quick-setup',
          this.selectedWallet.adminkey,
          {
            extension_id: extId,
            key_id: keyId,
            use_recommended_limits: true
          }
        )
        .then(response => {
          var count = response.data.length
          this.getPermissions()
          this.discoverExtensions()
          if (count > 0) {
            Quasar.Notify.create({
              message: count + ' permission(s) granted.',
              timeout: 1500
            })
          } else {
            Quasar.Notify.create({
              message: 'All permissions already granted.',
              timeout: 1000
            })
          }
        })
        .catch(err => {
          LNbits.utils.notifyApiError(err)
        })
    },
    allGranted(ext) {
      return ext.requirements.every(r => r.already_granted)
    },

    // --- Keys ---
    getKeys() {
      LNbits.api
        .request(
          'GET',
          '/nsecbunker/api/v1/keys',
          this.selectedWallet.adminkey
        )
        .then(response => {
          this.keys = response.data
        })
        .catch(err => {
          LNbits.utils.notifyApiError(err)
        })
    },
    importKey() {
      LNbits.api
        .request(
          'POST',
          '/nsecbunker/api/v1/keys',
          this.selectedWallet.adminkey,
          {private_key: this.newKeyInput}
        )
        .then(response => {
          this.newKeyInput = ''
          this.getKeys()
          Quasar.Notify.create({
            message: 'Key imported successfully.',
            timeout: 700
          })
        })
        .catch(err => {
          LNbits.utils.notifyApiError(err)
        })
    },
    generateKey() {
      LNbits.api
        .request(
          'POST',
          '/nsecbunker/api/v1/keys/generate',
          this.selectedWallet.adminkey
        )
        .then(response => {
          this.getKeys()
          Quasar.Notify.create({
            message: 'New key generated.',
            timeout: 700
          })
        })
        .catch(err => {
          LNbits.utils.notifyApiError(err)
        })
    },
    deleteKey(keyId) {
      LNbits.utils
        .confirmDialog(
          'Delete this key? All associated permissions will also be removed.'
        )
        .onOk(() => {
          LNbits.api
            .request(
              'DELETE',
              '/nsecbunker/api/v1/keys/' + keyId,
              this.selectedWallet.adminkey
            )
            .then(() => {
              this.getKeys()
              this.getPermissions()
              Quasar.Notify.create({message: 'Key deleted.', timeout: 700})
            })
            .catch(err => {
              LNbits.utils.notifyApiError(err)
            })
        })
    },
    editKey(key) {
      this.editKeyForm = {
        id: key.id,
        label: key.label || ''
      }
      this.showEditKeyDialog = true
    },
    updateKey() {
      LNbits.api
        .request(
          'PUT',
          '/nsecbunker/api/v1/keys/' + this.editKeyForm.id,
          this.selectedWallet.adminkey,
          {label: this.editKeyForm.label || null}
        )
        .then(response => {
          this.showEditKeyDialog = false
          this.getKeys()
          Quasar.Notify.create({
            message: 'Key updated.',
            timeout: 700
          })
        })
        .catch(err => {
          LNbits.utils.notifyApiError(err)
        })
    },

    // --- Permissions ---
    getPermissions() {
      LNbits.api
        .request(
          'GET',
          '/nsecbunker/api/v1/permissions',
          this.selectedWallet.adminkey
        )
        .then(response => {
          this.permissions = response.data
        })
        .catch(err => {
          LNbits.utils.notifyApiError(err)
        })
    },
    createPermission() {
      var kind =
        this.permForm.kind !== null
          ? this.permForm.kind
          : this.permForm.customKind
      if (kind === null || kind === '') {
        Quasar.Notify.create({
          type: 'warning',
          message: 'Please select an event kind.'
        })
        return
      }
      var payload = {
        key_id: this.permForm.key_id,
        extension_id: this.permForm.extension_id,
        kind: Number(kind),
        rate_limit_count: this.permForm.rate_limit_count || null,
        rate_limit_seconds: this.permForm.rate_limit_seconds || null
      }
      LNbits.api
        .request(
          'POST',
          '/nsecbunker/api/v1/permissions',
          this.selectedWallet.adminkey,
          payload
        )
        .then(response => {
          this.showPermDialog = false
          this.permForm = {
            key_id: null,
            extension_id: null,
            kind: null,
            customKind: null,
            rate_limit_count: null,
            rate_limit_seconds: null
          }
          this.getPermissions()
          this.discoverExtensions()
          Quasar.Notify.create({
            message: 'Permission granted.',
            timeout: 700
          })
        })
        .catch(err => {
          LNbits.utils.notifyApiError(err)
        })
    },
    editPermission(perm) {
      this.editPermForm = {
        id: perm.id,
        rate_limit_count: perm.rate_limit_count,
        rate_limit_seconds: perm.rate_limit_seconds
      }
      this.showEditPermDialog = true
    },
    updatePermission() {
      LNbits.api
        .request(
          'PUT',
          '/nsecbunker/api/v1/permissions/' + this.editPermForm.id,
          this.selectedWallet.adminkey,
          {
            rate_limit_count: this.editPermForm.rate_limit_count,
            rate_limit_seconds: this.editPermForm.rate_limit_seconds
          }
        )
        .then(response => {
          this.showEditPermDialog = false
          this.getPermissions()
          Quasar.Notify.create({
            message: 'Permission updated.',
            timeout: 700
          })
        })
        .catch(err => {
          LNbits.utils.notifyApiError(err)
        })
    },
    deletePermission(permId) {
      LNbits.utils.confirmDialog('Revoke this permission?').onOk(() => {
        LNbits.api
          .request(
            'DELETE',
            '/nsecbunker/api/v1/permissions/' + permId,
            this.selectedWallet.adminkey
          )
          .then(() => {
            this.getPermissions()
            this.discoverExtensions()
            Quasar.Notify.create({
              message: 'Permission revoked.',
              timeout: 700
            })
          })
          .catch(err => {
            LNbits.utils.notifyApiError(err)
          })
      })
    },

    // --- Logs ---
    getLogs(props) {
      var pagination = (props && props.pagination) || this.logPagination
      var page = pagination.page || 1
      var rowsPerPage = pagination.rowsPerPage || 20
      var offset = (page - 1) * rowsPerPage
      LNbits.api
        .request(
          'GET',
          '/nsecbunker/api/v1/log?offset=' + offset + '&limit=' + rowsPerPage,
          this.selectedWallet.adminkey
        )
        .then(response => {
          this.logs = response.data.data
          this.logPagination = Object.assign({}, pagination, {
            rowsNumber: response.data.total
          })
        })
        .catch(err => {
          LNbits.utils.notifyApiError(err)
        })
    },
  },
  created() {
    this.selectedWallet = this.g.user.wallets[0]
  }
})
