#include "http.h"
#include "parse.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/idr.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/mutex.h>

#define MODULE_NAME "vtfs"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("secs-dev");
MODULE_DESCRIPTION("A simple FS kernel module with RAM storage");

#define LOG(fmt, ...) pr_info("[" MODULE_NAME "]: " fmt, ##__VA_ARGS__)
#define VTFS_ROOT_INO 101

struct vtfs_file_content {
    char *data;
    size_t size;
    size_t allocated;
};

struct vtfs_file_info {
    char name[256];
    ino_t ino;
    ino_t parent_ino;
    bool is_dir;
    struct list_head list;
    struct vtfs_file_content content;
    struct mutex lock;
};

// Глобальный список файлов
static LIST_HEAD(vtfs_files);
// static int next_ino = 103;
static DEFINE_MUTEX(vtfs_files_lock);

// Прототипы функций
struct dentry* vtfs_mount(struct file_system_type* fs_type, int flags, const char* token, void* data);
void vtfs_kill_sb(struct super_block* sb);
int vtfs_fill_super(struct super_block *sb, void *data, int silent);
struct inode* vtfs_get_inode(struct super_block* sb, const struct inode* dir, umode_t mode, int i_ino);
int vtfs_iterate(struct file* filp, struct dir_context* ctx);
struct dentry* vtfs_lookup(struct inode* parent_inode, struct dentry* child_dentry, unsigned int flag);
int vtfs_create(struct mnt_idmap *idmap, struct inode *parent_inode, struct dentry *child_dentry, umode_t mode, bool b);
int vtfs_unlink(struct inode *parent_inode, struct dentry *child_dentry);
ssize_t vtfs_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset);
ssize_t vtfs_write(struct file *filp, const char __user *buffer, size_t length, loff_t *offset);
int vtfs_mkdir(struct mnt_idmap *idmap, struct inode *parent_inode, struct dentry *child_dentry, umode_t mode);
int vtfs_rmdir(struct inode *parent_inode, struct dentry *child_dentry);
int vtfs_link(struct dentry *old_dentry, struct inode *parent_dir, struct dentry *new_dentry);

// http
#define BUFFER_SIZE 4096
static char response_buffer[BUFFER_SIZE];
static char encoded_name[512];
static char encoded_content[4096];
static const char* AUTH_TOKEN = "AUTH_TOKEN";


struct vtfs_file_info *find_file_info(ino_t ino);
struct vtfs_file_info *find_file_in_dir(const char *name, ino_t parent_ino);


struct inode_operations vtfs_inode_ops = {
    .lookup = vtfs_lookup,
    .create = vtfs_create,
    .unlink = vtfs_unlink,
    .mkdir = vtfs_mkdir,
    .rmdir = vtfs_rmdir,
    .link = vtfs_link, // Добавили поддержку жестких ссылок
};

struct file_operations vtfs_dir_ops = {
    .iterate_shared = vtfs_iterate,
};

struct file_operations vtfs_file_ops = {
    .read = vtfs_read,
    .write = vtfs_write,
};

// статичные переменные
// static int mask = 0;

struct file_system_type vtfs_fs_type = {
    .name = "vtfs",
    .mount = vtfs_mount,
    .kill_sb = vtfs_kill_sb,
};

ssize_t vtfs_read(struct file *filp, char __user *buffer, size_t length, loff_t *offset) {
    struct inode *inode = filp->f_inode;
    char file_id[32];
    int64_t result;
    
    // Конвертируем inode файла в строку
    snprintf(file_id, sizeof(file_id), "%lu", inode->i_ino);
    
    // Получаем содержимое файла с сервера
    result = vtfs_http_call(AUTH_TOKEN, "download", response_buffer, BUFFER_SIZE, 1,
                           "id", file_id);
                           
    if (result < 0) {
        return result;
    }
    
    // Копируем данные в буфер пользователя
    if (copy_to_user(buffer, response_buffer, result))
        return -EFAULT;
    
    *offset += result;
    return result;
}

ssize_t vtfs_write(struct file *filp, const char __user *buffer, size_t length, loff_t *offset) {
    struct inode *inode = filp->f_inode;
    char file_id[32];
    char *temp_buffer;
    int64_t result;
    
    if (length > BUFFER_SIZE)  // Убедимся, что размер данных не превышает размер буфера
        return -ENOSPC;
        
    temp_buffer = kmalloc(length, GFP_KERNEL);  // Используем динамическую память для данных
    if (!temp_buffer)
        return -ENOMEM;  // Ошибка выделения памяти

    if (copy_from_user(temp_buffer, buffer, length)) {
        kfree(temp_buffer);  // Освобождаем память в случае ошибки
        return -EFAULT;
    }
    
    // URL encode содержимого
    encode(temp_buffer, encoded_content);

    // Конвертируем inode файла в строку
    snprintf(file_id, sizeof(file_id), "%lu", inode->i_ino);
    
    // Отправляем содержимое на сервер
    result = vtfs_http_call(AUTH_TOKEN, "upload", response_buffer, BUFFER_SIZE, 2,
                           "id", file_id,
                           "content", encoded_content);
                           
    kfree(temp_buffer);  // Освобождаем память после использования
    
    if (result < 0) {
        return result;
    }
    
    *offset += length;
    return length;
}



struct dentry* vtfs_mount(struct file_system_type* fs_type, int flags, const char* token, void* data) {
    struct dentry* ret = mount_nodev(fs_type, flags, data, vtfs_fill_super);
    if (ret == NULL) {
        printk(KERN_ERR "Can't mount file system");
    } else {
        printk(KERN_INFO "Mounted successfully");
    }
    return ret;
}

struct inode* vtfs_get_inode(struct super_block* sb, const struct inode* dir, umode_t mode, int i_ino) {
    struct inode *inode = new_inode(sb);
    if (inode != NULL) {
        inode->i_mode = mode;
        i_uid_write(inode, 0);
        i_gid_write(inode, 0);
        inode->i_ino = i_ino;
        
        inode->__i_atime = inode->__i_mtime = inode->__i_ctime = current_time(inode);
    }
    return inode;
}

struct dentry *vtfs_lookup(struct inode *parent_inode,
                           struct dentry *child_dentry,
                           unsigned int flag) {
    const char *name = child_dentry->d_name.name;
    struct vtfs_file_info *file_info;

    file_info = find_file_in_dir(name, parent_inode->i_ino);
    if (file_info) {
        struct inode *inode = vtfs_get_inode(
            parent_inode->i_sb,
            NULL,
            file_info->is_dir ? S_IFDIR : S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO,
            file_info->ino
        );

        if (inode) {
            inode->i_op = &vtfs_inode_ops;
            inode->i_fop = file_info->is_dir ? &vtfs_dir_ops : &vtfs_file_ops;
            d_add(child_dentry, inode);
        }
    }
    return NULL;
}

struct vtfs_file_info *find_file_info(ino_t ino) {
    struct vtfs_file_info *file_info;
    
    list_for_each_entry(file_info, &vtfs_files, list) {
        if (file_info->ino == ino) {
            return file_info;
        }
    }
    return NULL;
}

struct vtfs_file_info *find_file_in_dir(const char *name, ino_t parent_ino) {
    struct vtfs_file_info *file_info;

    list_for_each_entry(file_info, &vtfs_files, list) {
        if (file_info->parent_ino == parent_ino && strcmp(file_info->name, name) == 0) {
            return file_info;
        }
    }
    return NULL;
}

int vtfs_iterate(struct file *filp, struct dir_context *ctx) {
    struct dentry *dentry = filp->f_path.dentry;
    struct inode *inode = dentry->d_inode;
    char dir_id[32];
    int64_t result;
    
    // Обработка . и ..
    if (ctx->pos == 0) {
        if (!dir_emit(ctx, ".", 1, inode->i_ino, DT_DIR))
            return 0;
        ctx->pos++;
        return 1;
    }
    if (ctx->pos == 1) {
        ino_t parent_ino = dentry->d_parent->d_inode->i_ino;
        if (!dir_emit(ctx, "..", 2, parent_ino, DT_DIR))
            return 0;
        ctx->pos++;
        return 1;
    }

    // Если мы уже прочитали все файлы
    if (ctx->pos == 2) {
        // Запрашиваем список файлов с сервера
        snprintf(dir_id, sizeof(dir_id), "%lu", inode->i_ino);
        result = vtfs_http_call(AUTH_TOKEN, "list", response_buffer, BUFFER_SIZE, 1,
                               "parentId", dir_id);
                               
        if (result < 0) {
            return result;
        }
        
        // Убеждаемся что ответ заканчивается нулем
        response_buffer[BUFFER_SIZE - 1] = '\0';
    }
    
    // Парсим JSON ответ
    char* p = response_buffer;
    
    // Пропускаем все файлы до текущей позиции
    int current_pos = 2;  // Начинаем с 2, так как 0 и 1 - это . и ..
    
    // Ищем начало массива
    p = skip_whitespace(p);
    if (*p != '[')
        return 0;
    p++;
    
    while (current_pos < ctx->pos) {
        struct file_entry entry;
        p = skip_whitespace(p);
        
        if (*p == ']')  // Конец массива
            return 0;
            
        p = parse_file_entry(p, &entry);
        if (!p)
            return -EIO;  // Ошибка парсинга
            
        p = skip_whitespace(p);
        if (*p == ',')
            p++;
            
        current_pos++;
    }
    
    // Парсим следующий файл
    struct file_entry entry;
    p = skip_whitespace(p);
    
    if (*p == ']')  // Конец массива
        return 0;
        
    p = parse_file_entry(p, &entry);
    if (!p)
        return -EIO;
        
    // Эмитим файл
    unsigned char type = entry.is_dir ? DT_DIR : DT_REG;
    if (!dir_emit(ctx, entry.name, strlen(entry.name), entry.ino, type))
        return 0;
        
    ctx->pos++;
    return 1;
}



int vtfs_fill_super(struct super_block *sb, void *data, int silent) {
    struct inode* inode = vtfs_get_inode(sb, NULL, S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO, 100);
    if (inode == NULL) {
        return -ENOMEM;
    }

    inode->i_op = &vtfs_inode_ops;
    inode->i_fop = &vtfs_dir_ops;
    sb->s_root = d_make_root(inode);
    if (sb->s_root == NULL) {
        return -ENOMEM;
    }
    printk(KERN_INFO "return 0\n");
    return 0;
}

void vtfs_kill_sb(struct super_block* sb) {
    struct vtfs_file_info *file_info, *tmp;
    
    list_for_each_entry_safe(file_info, tmp, &vtfs_files, list) {
        if (file_info->content.data) {
            kfree(file_info->content.data);
        }
        list_del(&file_info->list);
        kfree(file_info);
    }
    
    kill_litter_super(sb);
    printk(KERN_INFO "vtfs super block is destroyed. Unmount successfully.\n");
}

int vtfs_create(struct mnt_idmap *idmap, struct inode *parent_inode, 
                struct dentry *child_dentry, umode_t mode, bool b) {
    const char *name = child_dentry->d_name.name;
    char parent_id[32];
    int64_t result;

    // URL encode имени файла
    encode(name, encoded_name);
    
    // Конвертируем parent inode в строку
    snprintf(parent_id, sizeof(parent_id), "%lu", parent_inode->i_ino);
    
    // Вызываем API для создания файла
    result = vtfs_http_call(AUTH_TOKEN, "create", response_buffer, BUFFER_SIZE, 4,
                           "name", encoded_name,
                           "parentId", parent_id,
                           "isDir", "false",
                           "content", "");
                           
    if (result < 0) {
        return result;
    }

    // Создаем новый inode
    struct inode *inode = vtfs_get_inode(parent_inode->i_sb, NULL, 
                                       S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO,
                                       result); // Используем ID из ответа сервера
    
    if (!inode) {
        return -ENOMEM;
    }

    inode->i_op = &vtfs_inode_ops;
    inode->i_fop = &vtfs_file_ops;
    d_add(child_dentry, inode);
    
    return 0;
}


int vtfs_unlink(struct inode *parent_inode, struct dentry *child_dentry) {
    const char *name = child_dentry->d_name.name;
    struct vtfs_file_info *file_info, *tmp;
    
    list_for_each_entry_safe(file_info, tmp, &vtfs_files, list) {
        if (!strcmp(name, file_info->name)) {
            if (file_info->content.data) {
                kfree(file_info->content.data);
            }
            list_del(&file_info->list);
            kfree(file_info);
            break;
        }
    }
    
    return simple_unlink(parent_inode, child_dentry);
}

int vtfs_mkdir(struct mnt_idmap *idmap, struct inode *parent_inode,
               struct dentry *child_dentry, umode_t mode) {
    const char *name = child_dentry->d_name.name;
    char parent_id[32];
    int64_t result;
    
    // URL encode имени директории
    encode(name, encoded_name);
    
    // Конвертируем parent inode в строку
    snprintf(parent_id, sizeof(parent_id), "%lu", parent_inode->i_ino);
    
    // Вызываем API для создания директории
    result = vtfs_http_call(AUTH_TOKEN, "create", response_buffer, BUFFER_SIZE, 3,
                           "name", encoded_name,
                           "parentId", parent_id,
                           "isDir", "true");
                           
    if (result < 0) {
        return result;
    }

    // Создаем новый inode
    struct inode *inode = vtfs_get_inode(parent_inode->i_sb, NULL,
                                       S_IFDIR | mode,
                                       result); // Используем ID из ответа сервера
    
    if (!inode) {
        return -ENOMEM;
    }
    
    inode->i_op = &vtfs_inode_ops;
    inode->i_fop = &vtfs_dir_ops;
    d_add(child_dentry, inode);
    
    return 0;
}

int vtfs_rmdir(struct inode *parent_inode, struct dentry *child_dentry) {
    const char *name = child_dentry->d_name.name;
    struct vtfs_file_info *dir_info, *tmp;
    struct inode *dir_inode = d_inode(child_dentry);
    
    // Проверяем, что директория пуста
    if (!simple_empty(child_dentry))
        return -ENOTEMPTY;
    
    // Находим и удаляем информацию о директории
    list_for_each_entry_safe(dir_info, tmp, &vtfs_files, list) {
        if (!strcmp(name, dir_info->name) && dir_info->ino == dir_inode->i_ino) {
            list_del(&dir_info->list);
            kfree(dir_info);
            break;
        }
    }
    
    // Удаляем саму директорию
    return simple_rmdir(parent_inode, child_dentry);
}

int vtfs_link(struct dentry *old_dentry, struct inode *parent_dir, struct dentry *new_dentry) {
    struct inode *old_inode = old_dentry->d_inode;
    struct vtfs_file_info *old_file_info;
    struct vtfs_file_info *new_file_info;

    // Проверяем, является ли старый объект регулярным файлом
    if (!S_ISREG(old_inode->i_mode))
        return -EPERM;

    mutex_lock(&vtfs_files_lock);

    // Ищем информацию о старом файле
    old_file_info = find_file_info(old_inode->i_ino);
    if (!old_file_info) {
        mutex_unlock(&vtfs_files_lock);
        return -ENOENT;
    }

    // Проверяем, нет ли уже файла с таким именем в целевой директории
    if (find_file_in_dir(new_dentry->d_name.name, parent_dir->i_ino)) {
        mutex_unlock(&vtfs_files_lock);
        return -EEXIST;
    }

    // Создаем новую запись для жесткой ссылки
    new_file_info = kzalloc(sizeof(*new_file_info), GFP_KERNEL);
    if (!new_file_info) {
        mutex_unlock(&vtfs_files_lock);
        return -ENOMEM;
    }

    // Копируем информацию
    strncpy(new_file_info->name, new_dentry->d_name.name, sizeof(new_file_info->name) - 1);
    new_file_info->ino = old_file_info->ino; // Используем тот же inode
    new_file_info->parent_ino = parent_dir->i_ino;
    new_file_info->is_dir = false; // Жесткие ссылки для директорий запрещены
    new_file_info->content = old_file_info->content; // Ссылаемся на тот же контент
    mutex_init(&new_file_info->lock);

    list_add(&new_file_info->list, &vtfs_files);

    // Увеличиваем счетчик ссылок у старого inode
    ihold(old_inode);

    mutex_unlock(&vtfs_files_lock);

    // Создаем новый inode
    struct inode *new_inode = vtfs_get_inode(parent_dir->i_sb, NULL, old_inode->i_mode, new_file_info->ino);
    if (!new_inode)
        return -ENOMEM;

    d_instantiate(new_dentry, new_inode);
    return 0;
}


static int __init vtfs_init(void) {
    int ret = register_filesystem(&vtfs_fs_type);
    if (ret == 0) {
        LOG("VTFS joined the kernel\n");
    } else {
        LOG("Failed to register filesystem\n");
    }
    return ret;
}

static void __exit vtfs_exit(void) {
    unregister_filesystem(&vtfs_fs_type);
    LOG("VTFS left the kernel\n");
}

module_init(vtfs_init);
module_exit(vtfs_exit);